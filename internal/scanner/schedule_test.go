package scanner_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// scheduling returns a schedule over the fixture's database, as one replica.
func (f *runFixture) scheduling(t *testing.T, replica string) *scanner.Schedule {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	return scanner.NewSchedule(f.db, f.queue, quiet, replica)
}

// queued counts the scans waiting or running for the fixture's build.
func (f *runFixture) queued(t *testing.T) int {
	t.Helper()
	n, err := f.db.NewSelect().Model((*queue.Job)(nil)).
		Where("kind = ?", queue.Scan).
		Where("reference = ?", strconv.FormatInt(f.target, 10)).
		// Wrapped, because two arguments to one placeholder binds the first
		// and drops the second: this counted pending work alone, and every
		// assertion built on it read a running job as an absent one.
		Where("state IN (?)", bun.List([]queue.State{queue.Pending, queue.Running})).
		Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// ranJustNow records a finished scan run against the fixture's build, which is
// what a scan having happened looks like from the schedule's side.
func (f *runFixture) ranJustNow(t *testing.T) {
	t.Helper()
	run, err := finding.NewStore(f.db.DB).Begin(t.Context(), finding.Run{
		TargetID: f.target, Scanner: "stub",
		ScannerVersion: "9.9.9", DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := finding.NewStore(f.db.DB).Finish(t.Context(), run.ID, "9.9.9", "2026-08-28", "", nil); err != nil {
		t.Fatal(err)
	}
}

// anotherBuild declares a second build of the same product and returns its
// target. Nothing is filed against it.
func (f *runFixture) anotherBuild(t *testing.T, stream string) int64 {
	t.Helper()
	ctx := t.Context()
	cat := catalog.NewStore(f.db.DB)
	product, err := cat.ProductByName(ctx, "sonic")
	if err != nil {
		t.Fatal(err)
	}
	declared, err := cat.DeclareStream(ctx, product.ID, stream, catalog.Tag, nil)
	if err != nil {
		t.Fatal(err)
	}
	variant, err := cat.VariantByName(ctx, product.ID, "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := cat.TargetFor(ctx, declared.ID, variant.ID)
	if err != nil {
		t.Fatal(err)
	}
	return target.ID
}

// withInventory files an inventory against a build, which is what makes it a
// build the schedule considers at all.
func (f *runFixture) withInventory(t *testing.T, target int64, hash string) {
	t.Helper()
	ctx := t.Context()
	scan, outcome, err := ingest.NewStore(f.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target, ContentHash: hash,
		BuiltAt: time.Now().UTC().Add(-time.Hour), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := graph.NewStore(f.db.DB).Apply(ctx, target, scan.ID, graph.Snapshot{
		Root: root, Components: []graph.Described{swss, libnl},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: swss}, {Parent: swss, Child: libnl},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestABuildNothingHasScannedIsAskedFor(t *testing.T) {
	// The vulnerability data is produced here rather than by the build, so
	// a release that is never rebuilt has the same components it always
	// had and a different answer every month. An inventory arriving puts
	// one scan on the queue; nothing else asked for the next one.
	eachRun(t, func(t *testing.T, f *runFixture) {
		asked, err := f.scheduling(t, "one").Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if asked != 1 {
			t.Fatalf("asked for %d scans, want the one build that holds an inventory", asked)
		}
		if held := f.queued(t); held != 1 {
			t.Errorf("%d scans are queued for the build, want 1", held)
		}
	})
}

func TestABuildScannedRecentlyIsNotAskedForAgain(t *testing.T) {
	// The interval is the whole of the policy. Asking every cycle would put a
	// scan of everything on the queue every few minutes, and each would find
	// the same components and the same vulnerability data as the last.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		f.ranJustNow(t)

		asked, err := f.scheduling(t, "one").Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if asked != 0 {
			t.Errorf("a build scanned a moment ago was asked for again (%d)", asked)
		}

		// And it is asked for once the interval has passed, so the check above
		// is an interval rather than a refusal to ask at all.
		if err := setting.NewStore(f.db.DB).Set(ctx, setting.ScanEvery, "1ns"); err != nil {
			t.Fatal(err)
		}
		asked, err = f.scheduling(t, "one").Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if asked != 1 {
			t.Errorf("a build past its interval was not asked for (%d)", asked)
		}
	})
}

func TestABuildAlreadyOnTheQueueIsNotAskedForTwice(t *testing.T) {
	// A cycle every few minutes against an interval measured in days: a build
	// the queue has not reached yet would otherwise collect one job per cycle,
	// each of which does the same work when it finally runs.
	//
	// Driven past the tenth build on purpose. A job's reference is text and a
	// build's identifier is a number, and comparing them by converting inside
	// the query keeps one character on PostgreSQL — right for the first nine
	// builds and wrong for every one after. Every SQLite test starts from a
	// fresh file at one, so the whole class is invisible unless a test
	// insists on a two-digit
	// identifier.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		var tenth int64
		for i := range 12 {
			tenth = f.anotherBuild(t, fmt.Sprintf("2.%d.0", i))
		}
		if tenth < 10 {
			t.Fatalf("the last build declared is %d, which does not exercise the case", tenth)
		}
		f.withInventory(t, tenth, "hash-tenth")
		if _, err := f.queue.Add(ctx, queue.Scan, strconv.FormatInt(tenth, 10)); err != nil {
			t.Fatal(err)
		}
		// Nothing else is queued, deliberately. Converting inside the
		// query does not merely miss: on PostgreSQL a two-digit identifier
		// truncates to its first digit, which then matches whatever job holds
		// *that* reference. A queue holding the single-digit build too would
		// hide the fault behind a match against the wrong row.
		if held := f.queued(t); held != 0 {
			t.Fatalf("%d scans are queued for the fixture's own build", held)
		}

		if _, err := f.scheduling(t, "one").Once(ctx); err != nil {
			t.Fatal(err)
		}
		queuedFor := func(target int64) int {
			t.Helper()
			n, err := f.db.NewSelect().Model((*queue.Job)(nil)).
				Where("kind = ?", queue.Scan).
				Where("reference = ?", strconv.FormatInt(target, 10)).
				Count(ctx)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		if n := queuedFor(tenth); n != 1 {
			t.Errorf("%d scans are queued for build %d, want the one that was already there", n, tenth)
		}
		// The fixture's own build has never been scanned and nothing was
		// queued for it, so it is asked for — which is what says the check
		// above is about the one build rather than about asking for nothing.
		if n := queuedFor(f.target); n != 1 {
			t.Errorf("%d scans are queued for the build that was due one, want 1", n)
		}
	})
}

func TestABuildWithNoInventoryIsNotAskedFor(t *testing.T) {
	// A build is declared before anything is filed against it. Scanning one
	// with no components records a run that found nothing against a build that
	// has nothing — an empty answer that reads exactly like a clean one.
	eachRun(t, func(t *testing.T, f *runFixture) {
		empty := f.anotherBuild(t, "2.4.0")
		asked, err := f.scheduling(t, "one").Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if asked != 1 {
			t.Fatalf("asked for %d, want only the build that holds an inventory", asked)
		}
		n, err := f.db.NewSelect().Model((*queue.Job)(nil)).
			Where("kind = ?", queue.Scan).
			Where("reference = ?", strconv.FormatInt(empty, 10)).
			Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("a build holding no inventory was queued for scanning")
		}
	})
}

func TestOnlyTheReplicaHoldingTheLeaseDecidesWhatToScanAgain(t *testing.T) {
	// Two replicas reading the same list at the same moment would both see the
	// same build as due and both queue a scan for it — the check that nothing
	// is queued already is made when the list is read, which is before either
	// of them has written anything.
	//
	// Driven by holding the lease rather than by racing two of them: a race
	// that happens to serialize proves nothing, and on the engine held to one
	// connection it always would.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		leases := queue.NewLeases(f.db.DB)
		mine, err := leases.Take(ctx, scanner.ScheduleLease, "the-other-replica", time.Hour)
		if err != nil || !mine {
			t.Fatalf("take the lease: %v %v", mine, err)
		}

		// Something is due — the fixture's build has never been scanned — and
		// this replica still does nothing, because the work is not its turn.
		asked, err := f.scheduling(t, "one").Once(ctx)
		if err != nil {
			t.Fatalf("a replica without the lease reported a failure: %v", err)
		}
		if asked != 0 {
			t.Errorf("a replica that does not hold the lease asked for %d scans", asked)
		}
		if held := f.queued(t); held != 0 {
			t.Errorf("%d scans were queued by a replica that does not hold the lease", held)
		}

		// And once the holder lets go, the work happens — so the check above
		// is about the lease rather than about there being nothing to do.
		if err := leases.Release(ctx, scanner.ScheduleLease, "the-other-replica"); err != nil {
			t.Fatal(err)
		}
		asked, err = f.scheduling(t, "one").Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if asked != 1 {
			t.Errorf("asked for %d scans once the lease was free, want 1", asked)
		}
	})
}

func TestAnotherProducersBacklogDoesNotStopTheAsking(t *testing.T) {
	// The cap exists so a runaway producer cannot push everyone else's work
	// behind its own. Counted across every kind it did the opposite: a bulk
	// change to the routing rules filled the queue and then refused every
	// scan and every upload in the deployment.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		full := queue.New(f.db, queue.Options{
			MaxAttempts: 5, MaxBacklog: 1, ClaimTimeout: 30 * time.Minute,
			Heartbeat: 5 * time.Minute, Backoff: 30 * time.Second,
		})
		if _, err := full.Add(ctx, queue.Route, "a-bulk-rule-change"); err != nil {
			t.Fatal(err)
		}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		asked, err := scanner.NewSchedule(f.db, full, quiet, "one").Once(ctx)
		if err != nil {
			t.Fatalf("another producer's backlog was reported as a failure: %v", err)
		}
		if asked != 1 {
			t.Errorf("asked for %d scans while another kind's queue was full, want 1", asked)
		}
	})
}

func TestAFullQueueStopsTheAskingRatherThanFailing(t *testing.T) {
	// Work due stays due. Pressing on would push a producer's arriving
	// inventories behind a re-scan of something last measured yesterday, and
	// failing would turn a full queue into an error nobody can act on.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		full := queue.New(f.db, queue.Options{
			MaxAttempts: 5, MaxBacklog: 1, ClaimTimeout: 30 * time.Minute,
			Heartbeat: 5 * time.Minute, Backoff: 30 * time.Second,
		})
		// Filled with the kind the schedule produces. A backlog is per kind,
		// so another producer's queue is not what stops this one.
		if _, err := full.Add(ctx, queue.Scan, "something-else"); err != nil {
			t.Fatal(err)
		}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		asked, err := scanner.NewSchedule(f.db, full, quiet, "one").Once(ctx)
		if err != nil {
			t.Fatalf("a full queue was reported as a failure: %v", err)
		}
		if asked != 0 {
			t.Errorf("asked for %d scans against a full queue", asked)
		}
	})
}

func TestACycleWorthOfScanningAlreadyWaitingStopsTheAsking(t *testing.T) {
	// The other short circuit. The test above fills the queue to its
	// *backlog* bound, so it is the queue refusing; this is the schedule
	// declining to ask at all because a cycle's worth is already waiting. Nothing this pass could add would be reached before
	// the next cycle anyway, and asking while the queue is this deep is how a
	// producer's arriving inventories end up behind re-scans of things
	// measured yesterday.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		roomy := queue.New(f.db, queue.Options{
			MaxAttempts: 5, MaxBacklog: 10_000, ClaimTimeout: 30 * time.Minute,
			Heartbeat: 5 * time.Minute, Backoff: 30 * time.Second,
		})
		// A cycle's worth of scans already queued, none of them this build's.
		// Numbered, because the bound is on queued *builds*: a reference that
		// is not a number does not name one and is dropped before the count.
		for i := range 200 {
			if _, err := roomy.Add(ctx, queue.Scan, strconv.Itoa(1_000_000+i)); err != nil {
				t.Fatal(err)
			}
		}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		asked, err := scanner.NewSchedule(f.db, roomy, quiet, "one").Once(ctx)
		if err != nil {
			t.Fatalf("a deep queue was reported as a failure: %v", err)
		}
		if asked != 0 {
			t.Errorf("asked for %d more scans with a cycle's worth already waiting", asked)
		}
	})
}

func TestTheScheduleAsksOnItsOwnAndReturnsWhenCancelled(t *testing.T) {
	// Schedule.Run is what cmd/openpsirt starts. What lives only in the loop
	// is the timer reset and the cancellation, and Once is correct whether or
	// not either is.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx, stop := context.WithCancel(t.Context())
		defer stop()

		// Due, so the first wake has something to ask for.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Run)(nil)).
			Set("finished_at = ?", time.Now().UTC().Add(-90*24*time.Hour)).
			Where("target_id = ?", f.target).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		schedule := scanner.NewSchedule(f.db, f.queue, quiet, "one")
		returned := make(chan struct{})
		go func() {
			defer close(returned)
			schedule.Run(ctx, time.Hour)
		}()

		waitFor(t, func() bool {
			n, err := f.db.DB.NewSelect().Model((*queue.Job)(nil)).
				Where("kind = ?", queue.Scan).Count(ctx)
			return err == nil && n > 0
		}, "the schedule to ask for a scan on its own")

		stop()
		select {
		case <-returned:
		case <-time.After(10 * time.Second):
			t.Fatal("the loop did not return when its context ended")
		}
	})
}
