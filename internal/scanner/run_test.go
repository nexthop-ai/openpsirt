// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// stub stands in for a scanner, so what the runner does with an answer is
// testable without a scanner and its database being installed.
type stub struct {
	saw      []byte
	reported []finding.Reported
	caution  string
	fail     error
	// interrupt, where set, is what a shutdown does while the scanner is
	// running: the scan's context ends under it.
	interrupt func()
}

func (s *stub) Name() string { return "stub" }

func (s *stub) Scan(ctx context.Context, inventory io.Reader) (scanner.Result, error) {
	s.saw, _ = io.ReadAll(inventory)
	if s.interrupt != nil {
		s.interrupt()
		return scanner.Result{}, ctx.Err()
	}
	if s.fail != nil {
		return scanner.Result{}, s.fail
	}
	return scanner.Result{
		Version: "9.9.9", DatabaseVersion: "2026-08-28",
		Caution:  s.caution,
		Reported: s.reported,
	}, nil
}

func at(name, version string) graph.Described {
	return graph.Described{
		Purl: "pkg:deb/debian/" + name + "@" + version, Name: name, Version: version,
	}
}

var (
	root  = at("sonic", "1.0")
	swss  = at("libswsscommon", "1.0.0")
	libnl = at("libnl-3-200", "3.7.0")
)

type runFixture struct {
	db     *database.DB
	queue  *queue.Queue
	target int64
}

func eachRun(t *testing.T, fn func(t *testing.T, f *runFixture)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		target, err := cat.Resolve(ctx, "sonic", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}

		// The inventory the build shipped, already read and stored.
		scan, outcome, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
			TargetID: target.ID, ContentHash: "hash-1",
			BuiltAt: time.Now().UTC().Add(-time.Hour), ParserVersion: "test",
		})
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record scan: %v %v", outcome, err)
		}
		_, err = graph.NewStore(db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
			Root: root, Components: []graph.Described{swss, libnl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss}, {Parent: swss, Child: libnl},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		fn(t, &runFixture{db: db, queue: queue.New(db, queue.DefaultOptions()), target: target.ID})
	})
}

// waiting leaves the work behind that an arriving inventory would.
func (f *runFixture) waiting(t *testing.T) {
	t.Helper()
	if _, err := f.queue.Add(t.Context(), queue.Scan, strconv.FormatInt(f.target, 10)); err != nil {
		t.Fatal(err)
	}
}

func TestScanningATargetProducesFindings(t *testing.T) {
	eachRun(t, func(t *testing.T, f *runFixture) {
		s := &stub{reported: []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl, FixState: finding.FixedUpstream, FixedIn: "3.9.0",
		}}}
		f.waiting(t)

		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		outcome, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Once(t.Context())
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if outcome == nil {
			t.Fatal("there was work waiting and nothing was done")
		}
		if outcome.Applied.Opened != 1 {
			t.Errorf("opened %d findings, want 1", outcome.Applied.Opened)
		}

		// The scanner is given what we stored, not what a build sent — the
		// file it sent is not kept for a moving line.
		if outcome.Components != 2 {
			t.Errorf("scanned %d components, want 2", outcome.Components)
		}
		for _, want := range []string{"libnl-3-200", "libswsscommon", "pkg:deb/debian/"} {
			if !bytes.Contains(s.saw, []byte(want)) {
				t.Errorf("the scanner was not given %q", want)
			}
		}
		// The product itself is not a package any database has heard of.
		if bytes.Contains(s.saw, []byte("\"sonic\"")) {
			t.Error("the product was sent to the scanner as though it were a package")
		}
	})
}

func TestABuildHoldingNothingButItselfIsScannedWithoutTheScanner(t *testing.T) {
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		scan, outcome, err := ingest.NewStore(f.db.DB).Record(ctx, ingest.Arriving{
			TargetID: f.target, ContentHash: "hash-root-only",
			BuiltAt: time.Now().UTC().Add(-time.Minute), ParserVersion: "test",
		})
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record scan: %v %v", outcome, err)
		}
		if _, err := graph.NewStore(f.db.DB).Apply(ctx, f.target, scan.ID,
			graph.Snapshot{Root: root}); err != nil {
			t.Fatal(err)
		}
		// What the real scanner does with an inventory of no components.
		s := &stub{fail: errors.New("exit status 2")}
		f.waiting(t)

		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		done, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Once(ctx)
		if err != nil {
			t.Fatalf("a build with nothing in it failed its scan: %v", err)
		}
		if done == nil || done.Components != 0 {
			t.Fatalf("the scan reported %+v, want one of no components", done)
		}
		if s.saw != nil {
			t.Error("the scanner was asked about a build holding nothing")
		}
	})
}

func TestWhatRanIsRecordedAgainstTheRun(t *testing.T) {
	// A finding that appeared or vanished because the scanner or its data
	// moved is unexplainable without this.
	eachRun(t, func(t *testing.T, f *runFixture) {
		s := &stub{}
		f.waiting(t)
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		outcome, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		var run finding.Run
		if err := f.db.DB.NewSelect().Model(&run).Where("id = ?", outcome.RunID).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if run.Scanner != "stub" || run.ScannerVersion != "9.9.9" || run.DatabaseVersion != "2026-08-28" {
			t.Errorf("recorded %+v", run)
		}
		if !run.RanHere {
			t.Error("a scan we ran says it came from a producer")
		}
		if run.FinishedAt == nil {
			t.Error("a run that ended is still open")
		}
	})
}

func TestAScannerThatFailedIsRecordedAsOne(t *testing.T) {
	// A scanner that stopped working is otherwise indistinguishable from a
	// product that stopped having problems.
	eachRun(t, func(t *testing.T, f *runFixture) {
		s := &stub{fail: errors.New("database is corrupt")}
		f.waiting(t)
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if _, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Once(t.Context()); err == nil {
			t.Fatal("a failed scan reported success")
		}

		var run finding.Run
		if err := f.db.DB.NewSelect().Model(&run).Limit(1).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if run.Failure == "" {
			t.Error("a run that failed does not say why")
		}
		if run.FinishedAt == nil {
			t.Error("a run that failed is still open")
		}
	})
}

func TestScanningAgainWithTheSameAnswerWritesNothing(t *testing.T) {
	eachRun(t, func(t *testing.T, f *runFixture) {
		reported := []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl,
		}}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		runner := scanner.NewRunner(f.db, f.queue, &stub{reported: reported}, quiet, "test")

		f.waiting(t)
		if _, err := runner.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.waiting(t)
		outcome, err := runner.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !outcome.Applied.Unchanged() {
			t.Errorf("a re-scan finding the same things wrote %+v", outcome.Applied)
		}
	})
}

func TestThereIsNothingToScanWhenNothingIsWaiting(t *testing.T) {
	eachRun(t, func(t *testing.T, f *runFixture) {
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		outcome, err := scanner.NewRunner(f.db, f.queue, &stub{}, quiet, "test").Once(t.Context())
		if err != nil || outcome != nil {
			t.Errorf("an empty queue produced %+v (%v)", outcome, err)
		}
	})
}

// decided records an agreed claim about the one issue in this build, the way
// somebody triaging would: keyed on where the finding sits and the versions it
// has now.
func (f *runFixture) decided(t *testing.T) int64 {
	t.Helper()
	ctx := t.Context()

	rights := access.NewStore(f.db.DB)
	product, err := catalog.NewStore(f.db.DB).ProductByName(ctx, "sonic")
	if err != nil {
		t.Fatal(err)
	}
	var people []access.Subject
	for _, who := range []string{"proposer", "approver"} {
		person, err := rights.Ensure(ctx, who, "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, person.ID, product.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		subject, err := rights.Resolve(ctx, who)
		if err != nil {
			t.Fatal(err)
		}
		people = append(people, subject)
	}

	issue, err := finding.NewVulnerabilities(f.db.DB).ByName(ctx, "CVE-2026-1")
	if err != nil {
		t.Fatal(err)
	}
	where, err := finding.NewStore(f.db.DB).PlaceFor(ctx, people[0], f.target, issue,
		finding.PlaceIdentity("libnl-3-200", "libswsscommon"))
	if err != nil {
		t.Fatal(err)
	}

	store := triage.NewStore(f.db.DB)
	made, err := store.Propose(ctx, people[0], triage.Proposal{
		Place: triage.Place{
			ProductID: where.ProductID, VulnerabilityID: where.VulnerabilityID,
			PlaceIdentity: where.PlaceIdentity, Visibility: where.Visibility,
			ComponentUpstream: where.ComponentUpstream, ConsumerUpstream: where.ConsumerUpstream,
		},
		Outcome: triage.NotApplicable, Justification: triage.CodeNotInExecutePath,
		Reasoning: "The parser is never reached: we only call the encoder.",
		By:        people[0].ID, NeedsApproval: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Agreed to as a claim, which is what agreeing is: one act is one
	// argument, and this row is where it lands.
	if _, err := store.ApproveClaim(ctx, people[1], made.ClaimID, "", nil, ""); err != nil {
		t.Fatal(err)
	}
	return made.ID
}

// rebuilt stores a second inventory, optionally moving the library's version.
func (f *runFixture) rebuilt(t *testing.T, library graph.Described) {
	t.Helper()
	ctx := t.Context()
	scan, outcome, err := ingest.NewStore(f.db.DB).Record(ctx, ingest.Arriving{
		TargetID: f.target, ContentHash: "hash-2",
		BuiltAt: time.Now().UTC(), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := graph.NewStore(f.db.DB).Apply(ctx, f.target, scan.ID, graph.Snapshot{
		Root: root, Components: []graph.Described{swss, library},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: swss}, {Parent: swss, Child: library},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// scan runs the scanner over whatever is currently stored.
func (f *runFixture) scan(t *testing.T, component graph.Described) *scanner.Outcome {
	t.Helper()
	f.waiting(t)
	s := &stub{reported: []finding.Reported{{
		Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
		Component: component, FixState: finding.FixedUpstream, FixedIn: "3.9.0",
	}}}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	outcome, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Once(t.Context())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if outcome == nil {
		t.Fatal("there was work waiting and nothing was done")
	}
	return outcome
}

func TestAScanMarksTheJudgmentsItMovedOutFromUnder(t *testing.T) {
	// The half that is not automatic. A decision stops applying on its own
	// when the versions move, because what applies is matched on them — but
	// nobody finds out. Without this the finding reappears as though it had
	// never been looked at, with the reasoning stranded on a row nothing
	// points at, which is exactly what keeping the old decision is for.
	eachRun(t, func(t *testing.T, f *runFixture) {
		f.scan(t, libnl)
		f.decided(t)

		// The library moves under an unchanged consumer: the ordinary case.
		moved := at("libnl-3-200", "3.9.0")
		f.rebuilt(t, moved)
		outcome := f.scan(t, moved)

		if outcome.Lapsed != 1 {
			t.Fatalf("a version bump marked %d judgments, want 1", outcome.Lapsed)
		}

		// And it reads as superseded rather than having quietly vanished.
		rights := access.NewStore(f.db.DB)
		who, err := rights.Resolve(t.Context(), "approver")
		if err != nil {
			t.Fatal(err)
		}
		decisions, _, _, err := triage.NewStore(f.db.DB).List(t.Context(), who, triage.Filter{}, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(decisions) != 1 || decisions[0].State != triage.LapsedState {
			t.Errorf("the superseded decision reads as %+v", decisions)
		}
	})
}

func TestWhoeverProposedItIsToldThatItLapsed(t *testing.T) {
	// A lapse is one of the two outcomes a proposer hears about by
	// message: nothing they did caused it, and it hands work back to them.
	eachRun(t, func(t *testing.T, f *runFixture) {
		f.scan(t, libnl)
		f.decided(t)

		moved := at("libnl-3-200", "3.9.0")
		f.rebuilt(t, moved)
		f.waiting(t)
		s := &stub{reported: []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: moved, FixState: finding.FixedUpstream, FixedIn: "3.9.0",
		}}}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if _, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").
			Telling(notify.Lapses(f.db.DB, quiet)).Once(t.Context()); err != nil {
			t.Fatalf("scan: %v", err)
		}

		rights := access.NewStore(f.db.DB)
		author, err := rights.Resolve(t.Context(), "proposer")
		if err != nil {
			t.Fatal(err)
		}
		waiting, _, err := notify.NewStore(f.db.DB).Waiting(t.Context(), author, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var said []string
		for _, one := range waiting {
			if one.Kind == notify.ClaimLapsed {
				said = append(said, one.Body)
			}
		}
		if len(said) != 1 {
			t.Fatalf("the proposer was told %d times that their decision lapsed: %v",
				len(said), said)
		}
		if !strings.Contains(said[0], "stopped applying") {
			t.Errorf("the notice does not say what happened: %q", said[0])
		}

		// And nobody else is: it is not their work that came back.
		other, err := rights.Resolve(t.Context(), "approver")
		if err != nil {
			t.Fatal(err)
		}
		theirs, _, err := notify.NewStore(f.db.DB).Waiting(t.Context(), other, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, one := range theirs {
			if one.Kind == notify.ClaimLapsed {
				t.Errorf("somebody who proposed nothing was told a decision lapsed: %q", one.Body)
			}
		}
	})
}

func TestARebuildThatMovedNothingMarksNothing(t *testing.T) {
	// The dangerous direction. A sweep that marked too much would quietly
	// unpick judgments nobody had revisited — nightly, since a rebuild is
	// nightly.
	eachRun(t, func(t *testing.T, f *runFixture) {
		f.scan(t, libnl)
		f.decided(t)

		f.rebuilt(t, libnl)
		if outcome := f.scan(t, libnl); outcome.Lapsed != 0 {
			t.Errorf("a rebuild that moved nothing marked %d judgments", outcome.Lapsed)
		}
	})
}

func TestAScanCutShortByShutdownHandsItsJobBack(t *testing.T) {
	// A shutdown cancels the scan. The job is handed back and the run is
	// closed with the same context the scan was canceled with, so without
	// care both writes fail too — and the job stays claimed by a process that
	// has gone until the claim goes stale, half an hour later, while the run
	// stays open for ever.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		s := &stub{interrupt: cancel}
		f.waiting(t)
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if _, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Once(ctx); err == nil {
			t.Fatal("an interrupted scan reported success")
		}

		var job queue.Job
		if err := f.db.DB.NewSelect().Model(&job).Limit(1).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if job.State != queue.Pending || job.ClaimedBy != nil {
			t.Errorf("the job is %s held by %v, want pending and held by nobody", job.State, job.ClaimedBy)
		}
		var run finding.Run
		if err := f.db.DB.NewSelect().Model(&run).Limit(1).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if run.FinishedAt == nil {
			t.Error("the run an interrupted scan began is still open")
		}
	})
}

func TestWhatTheScannerSaidWhileSucceedingReachesTheRun(t *testing.T) {
	// It was read only on failure, so a run that answered while warning that
	// its answer was coarse threw the warning away — and that warning
	// qualifies every finding the run produced.
	eachRun(t, func(t *testing.T, f *runFixture) {
		const said = "go binary packages were found but none carry function symbols"
		s := &stub{caution: said, reported: []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}}}
		f.waiting(t)

		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if _, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Once(t.Context()); err != nil {
			t.Fatalf("scan: %v", err)
		}

		var runs []finding.Run
		if err := f.db.DB.NewSelect().Model(&runs).
			Where("finished_at IS NOT NULL").Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(runs) != 1 {
			t.Fatalf("%d finished runs", len(runs))
		}
		if runs[0].Caution != said {
			t.Errorf("the run kept %q", runs[0].Caution)
		}
		if runs[0].Failure != "" {
			t.Errorf("a run that warned reads as failed: %q", runs[0].Failure)
		}
	})
}

func TestTheRunnerScansUntilTheQueueIsEmptyAndReturnsQuietlyOnShutdown(t *testing.T) {
	// Runner.Run is what cmd/openpsirt starts and what scans every build this
	// server holds. Every other test here drives Once, and three things live
	// only in the loop — the queue being drained rather than one job taken per
	// wake, the timer being reset, and shutdown returning without reporting a
	// fault. Once is correct whether or not any of them is.
	//
	// The last one matters on its own. A read cut short by shutdown is handed
	// back and scanned again later, so it is not an error — and a process that
	// logged one at every stop would teach an operator to ignore the level
	// that means something.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx, stop := context.WithCancel(t.Context())
		defer stop()

		said := &recording{}
		runner := scanner.NewRunner(f.db, f.queue, &stub{reported: []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl,
		}}}, slog.New(said), "test")

		f.waiting(t)
		returned := make(chan struct{})
		go func() {
			defer close(returned)
			// Longer than this test runs for, so a second wake cannot be what
			// finishes the work.
			runner.Run(ctx, time.Hour)
		}()

		waitFor(t, func() bool { return f.finishedRuns(t) > 0 }, "the queued build to be scanned")

		stop()
		select {
		case <-returned:
		case <-time.After(10 * time.Second):
			t.Fatal("the loop did not return when its context ended")
		}
		if at, message := said.worst(); at >= slog.LevelError {
			t.Errorf("stopping reported %v: %q — a scan cut short by shutdown is "+
				"handed back rather than failed", at, message)
		}
	})
}

// finishedRuns is how many scan runs have finished against this build.
func (f *runFixture) finishedRuns(t *testing.T) int {
	t.Helper()
	n, err := f.db.DB.NewSelect().Model((*finding.Run)(nil)).
		Where("target_id = ?", f.target).
		Where("finished_at IS NOT NULL").
		Count(t.Context())
	if err != nil {
		t.Fatalf("count the scan runs: %v", err)
	}
	return n
}

// recording keeps the worst thing a loop said, so a test can assert that
// stopping said nothing at the level that means something is wrong.
type recording struct {
	mu      sync.Mutex
	level   slog.Level
	message string
}

func (r *recording) Enabled(context.Context, slog.Level) bool { return true }

func (r *recording) Handle(_ context.Context, record slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if record.Level >= r.level {
		r.level, r.message = record.Level, record.Message
	}
	return nil
}

func (r *recording) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recording) WithGroup(string) slog.Handler      { return r }

func (r *recording) worst() (slog.Level, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.level, r.message
}

// waitFor polls until done reports true. A deadline rather than a sleep: the
// loops under test are driven by a timer, so how long the work takes is not
// something a test can name.
func waitFor(t *testing.T, done func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waited for %s and it did not happen", what)
}
