// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
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
	world  *fixture.World
	queue  *queue.Queue
	target int64
}

func eachRun(t *testing.T, fn func(t *testing.T, f *runFixture)) {
	t.Helper()
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		fn(t, newRun(t, w))
	})
}

// newRun stores the inventory the build shipped in the world w seeded.
func newRun(t *testing.T, w *fixture.World) *runFixture {
	t.Helper()
	ctx := t.Context()
	db := w.DB
	target := w.Target

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

	return &runFixture{db: db, world: w, queue: queue.New(db, queue.DefaultOptions()), target: target.ID}
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
	product := f.world.Product
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

func TestAScanRatingAnIssueWorseLapsesAClaimTheRatingBearsOn(t *testing.T) {
	// A judgment that something does not matter much is not a judgment about
	// what it has become (REQ-25). Nothing moved in the build; the report
	// raised the issue from high to critical, and the proposer is told why.
	eachRun(t, func(t *testing.T, f *runFixture) {
		f.scan(t, libnl)
		decided := f.decided(t)
		// A claim a severity bears on, made against the rating the issue had.
		if _, err := f.db.DB.NewUpdate().Table("claim").
			Set("justification = ?", string(triage.CodeNotReachableByAdversary)).
			Where(`id = (SELECT claim_id FROM "decision" WHERE id = ?)`, decided).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Table("decision").
			Set("severity_centi = ?", 800).Where("id = ?", decided).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		f.rebuilt(t, libnl)
		f.waiting(t)
		s := &stub{reported: []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "critical", Score: 9.8},
			Component: libnl, FixState: finding.FixedUpstream, FixedIn: "3.9.0",
		}}}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		outcome, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").
			Telling(notify.Lapses(f.db.DB, quiet)).Once(t.Context())
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if outcome.Lapsed != 1 {
			t.Errorf("a scan rating the issue worse marked %d judgments, want 1", outcome.Lapsed)
		}

		author, err := access.NewStore(f.db.DB).Resolve(t.Context(), "proposer")
		if err != nil {
			t.Fatal(err)
		}
		waiting, _, err := notify.NewStore(f.db.DB).Waiting(t.Context(), author, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		told := false
		for _, one := range waiting {
			if one.Kind == notify.ClaimLapsed && strings.Contains(one.Body, "rated worse") {
				told = true
			}
		}
		if !told {
			t.Error("the proposer was not told the issue was rated worse")
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
	// A scanner can answer while warning that its answer is coarse, and that
	// warning qualifies every finding the run produced, so it is kept on a
	// run that succeeded as well as on one that failed.
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
	//
	// Two builds are queued before the loop starts, and the wake interval is
	// longer than the test, so only draining reaches the second. Verified by
	// breaking the drain loop after its first scan: the second build is never
	// scanned and the wait times out.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx, stop := context.WithCancel(t.Context())
		defer stop()

		said := &recording{}
		runner := scanner.NewRunner(f.db, f.queue, &stub{reported: []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl,
		}}}, slog.New(said), "test")

		f.waiting(t)
		second := f.anotherBuild(t, "202411")
		f.withInventory(t, second, "sha256:second")
		if _, err := f.queue.Add(ctx, queue.Scan, strconv.FormatInt(second, 10)); err != nil {
			t.Fatal(err)
		}
		returned := make(chan struct{})
		go func() {
			defer close(returned)
			// Longer than this test runs for, so a second wake cannot be what
			// finishes the work.
			runner.Run(ctx, time.Hour)
		}()

		waitFor(t, func() bool { return f.finishedRuns(t) > 0 && f.finishedRunsOn(t, second) > 0 },
			"both queued builds to be scanned")

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
	return f.finishedRunsOn(t, f.target)
}

// finishedRunsOn is how many scan runs have finished against a build.
func (f *runFixture) finishedRunsOn(t *testing.T, target int64) int {
	t.Helper()
	n, err := f.db.DB.NewSelect().Model((*finding.Run)(nil)).
		Where("target_id = ?", target).
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

// A scan is where the tables move furthest, and SQLite gathers no statistics
// unless asked, so a scan leaves the finding table with statistics behind it.
// Without them the review queue walks every finding under one component.
func TestAScanLeavesSQLiteWithStatisticsForTheFindings(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		f := newRun(t, fixture.New(t, db))
		var reported []finding.Reported
		for i := range 50 {
			reported = append(reported, finding.Reported{
				Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%d", 1000+i), Severity: "high"},
				Component: libnl, FixState: finding.FixedUpstream, FixedIn: "3.9.0",
			})
		}
		f.waiting(t)
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if _, err := scanner.NewRunner(f.db, f.queue, &stub{reported: reported}, quiet, "test").
			Once(t.Context()); err != nil {
			t.Fatalf("scan: %v", err)
		}
		var n int
		if err := f.db.QueryRowContext(t.Context(),
			`SELECT COUNT(*) FROM "sqlite_stat1" WHERE "tbl" = 'finding'`).Scan(&n); err != nil || n == 0 {
			t.Errorf("a scan left the finding table without statistics (%d rows, %v)", n, err)
		}
	})
}

func TestARunRecordsTheCVERecordSnapshotItRead(t *testing.T) {
	eachRun(t, func(t *testing.T, f *runFixture) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, cverecord.FileName), snapshotFile(t), 0o600); err != nil {
			t.Fatal(err)
		}
		f.waiting(t)
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		outcome, err := scanner.NewRunner(f.db, f.queue, &stub{}, quiet, "test").
			Narrowing(cverecord.NewHeld(dir)).Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var run finding.Run
		if err := f.db.DB.NewSelect().Model(&run).Where("id = ?", outcome.RunID).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if run.RecordsVersion != "2026-10-07T00:00:00Z" {
			t.Errorf("the run recorded snapshot %q, want the one it read", run.RecordsVersion)
		}
	})
}

func TestAnUnreadableSnapshotFailsTheRunAndSaysSo(t *testing.T) {
	// Run without it, every finding a record had closed would open again and
	// close again on the next run that reads one.
	eachRun(t, func(t *testing.T, f *runFixture) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, cverecord.FileName), []byte("damaged"), 0o600); err != nil {
			t.Fatal(err)
		}
		f.waiting(t)
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		s := &stub{reported: []finding.Reported{{Issue: finding.Named{Identifier: "CVE-2026-1"}, Component: libnl}}}
		if _, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").
			Narrowing(cverecord.NewHeld(dir)).Once(t.Context()); err == nil {
			t.Fatal("a scan with a damaged snapshot reported success")
		}
		var run finding.Run
		if err := f.db.DB.NewSelect().Model(&run).Limit(1).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(run.Failure, "CVE record snapshot") || run.FinishedAt == nil {
			t.Errorf("the run ended %v saying %q, want it ended naming the snapshot", run.FinishedAt, run.Failure)
		}
		if s.saw != nil {
			t.Error("the scanner ran although the run could not narrow what it found")
		}
	})
}

// snapshotFile is a snapshot of no records, taken at a known moment.
func snapshotFile(t *testing.T) []byte {
	t.Helper()
	var written bytes.Buffer
	if err := cverecord.Write(&written, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC), "", nil); err != nil {
		t.Fatal(err)
	}
	return written.Bytes()
}

// kernelShipped replaces what the build ships with an upstream kernel, as a
// build naming the tarball it built from describes it.
func (f *runFixture) kernelShipped(t *testing.T, version string) graph.Described {
	t.Helper()
	ctx := t.Context()
	kernel := graph.Described{
		Name: "linux", Version: version, Purl: "pkg:generic/linux@" + version,
		CPE: "cpe:2.3:o:linux:linux_kernel:" + version + ":*:*:*:*:*:*:*",
	}
	scan, outcome, err := ingest.NewStore(f.db.DB).Record(ctx, ingest.Arriving{
		TargetID: f.target, ContentHash: "hash-kernel-" + version,
		BuiltAt: time.Now().UTC(), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := graph.NewStore(f.db.DB).Apply(ctx, f.target, scan.ID, graph.Snapshot{
		Root: root, Components: []graph.Described{kernel},
		Dependencies: []graph.Dependency{{Parent: root, Child: kernel}},
	}); err != nil {
		t.Fatal(err)
	}
	return kernel
}

// fixedOn618 is a snapshot holding one kernel record, fixed on 6.18.y at
// 6.18.27.
func fixedOn618(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	var written bytes.Buffer
	if err := cverecord.Write(&written, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC), "", []cverecord.Record{{
		ID: "CVE-2026-31589", Affected: []cverecord.Entry{{Vendor: "Linux", Product: "Linux",
			DefaultStatus: "affected", Versions: []cverecord.Line{
				{Version: "6.14", Status: "affected"},
				{Version: "6.18.27", LessThanOrEqual: "6.18.*", Status: "unaffected", VersionType: "semver"},
			}}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cverecord.FileName), written.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAScanClosesWhatTheIssuesRecordExcludes(t *testing.T) {
	eachRun(t, func(t *testing.T, f *runFixture) {
		kernel := f.kernelShipped(t, "6.18.55")
		f.waiting(t)
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		// The scanner's account carries no CPE: what is tied is the build's
		// own description of the component.
		s := &stub{reported: []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-31589"},
			Component: graph.Described{Name: kernel.Name, Version: kernel.Version, Purl: kernel.Purl},
		}}}
		outcome, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").
			Narrowing(cverecord.NewHeld(fixedOn618(t))).Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Applied.Unaffected != 1 || outcome.Applied.Opened != 0 {
			t.Errorf("unaffected %d and opened %d, want the one finding recorded unaffected",
				outcome.Applied.Unaffected, outcome.Applied.Opened)
		}
		var rows []finding.Finding
		if err := f.db.DB.NewSelect().Model(&rows).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].ClosedBecause != finding.Unaffected || rows[0].UnaffectedBy == "" {
			t.Errorf("recorded %+v, want one row closed as unaffected with the record's lines", rows)
		}
	})
}

func TestABuildLastScannedWithASnapshotIsNotScannedWithoutOne(t *testing.T) {
	// A replica restarted on scratch space holds none until its first fetch,
	// and a scan then would open every finding a record had closed.
	eachRun(t, func(t *testing.T, f *runFixture) {
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		f.waiting(t)
		if _, err := scanner.NewRunner(f.db, f.queue, &stub{}, quiet, "test").
			Narrowing(cverecord.NewHeld(fixedOn618(t))).Once(t.Context()); err != nil {
			t.Fatal(err)
		}

		empty := t.TempDir()
		f.waiting(t)
		s := &stub{}
		if _, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").
			Narrowing(cverecord.NewHeld(empty)).Once(t.Context()); err == nil {
			t.Fatal("a build last scanned with a snapshot was scanned without one")
		}
		if s.saw != nil {
			t.Error("the scanner ran although nothing could narrow what it found")
		}

		var refused finding.Run
		if err := f.db.DB.NewSelect().Model(&refused).Order("id DESC").Limit(1).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(refused.Failure, "no CVE record snapshot") {
			t.Errorf("the refused run says %q, want it to name the missing snapshot", refused.Failure)
		}
	})
}

func TestABuildNeverScannedWithASnapshotIsScannedWithoutOne(t *testing.T) {
	eachRun(t, func(t *testing.T, f *runFixture) {
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		f.waiting(t)
		if _, err := scanner.NewRunner(f.db, f.queue, &stub{}, quiet, "test").
			Narrowing(cverecord.NewHeld(t.TempDir())).Once(t.Context()); err != nil {
			t.Errorf("a build never narrowed was refused without a snapshot: %v", err)
		}
	})
}
