// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func TestUnheldWorkNoArrivalSweptIsPlacedByTheCatchUp(t *testing.T) {
	// Work opened with no sweep queued, as before a deployment queued one on
	// arrival or while the sweep queue was full, is placed by the catch-up
	// with nothing else arriving.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.ruled(t)
		if _, err := f.store.Apply(ctx, f.build, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		if n := f.sweeps(t); n != 0 {
			t.Fatalf("%d sweeps were queued by a scan applied with no queue", n)
		}

		work := queue.New(f.db, queue.DefaultOptions())
		sweeper := finding.NewSweeper(f.db, work, slog.New(slog.NewTextHandler(io.Discard, nil)), "one")
		queued, err := sweeper.CatchUpOnce(ctx, queue.NewLeases(f.db.DB))
		if err != nil {
			t.Fatal(err)
		}
		if queued != 1 {
			t.Fatalf("the catch-up queued %d sweeps for one ruled product, want one", queued)
		}
		if _, _, err := sweeper.Once(ctx); err != nil {
			t.Fatal(err)
		}
		for _, row := range f.open(t) {
			if row.AssignedTo == nil {
				t.Errorf("finding %d on libnl is unheld after the catch-up", row.ID)
			}
		}
	})
}

// lapse moves the catch-up's lease past its expiry, as a day passing does.
func lapse(t *testing.T, f *fixture) {
	t.Helper()
	past := time.Now().UTC().Add(-time.Minute)
	if _, err := f.db.DB.NewUpdate().Model((*queue.Lease)(nil)).
		Set(`"held_until" = ?`, past).
		Where(`"name" = ?`, finding.CatchUpLease).
		Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestTheCatchUpQueuesOnlyRuledProducts(t *testing.T) {
	// A product with no rule in force placing findings has nothing to catch
	// up.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		work := queue.New(f.db, queue.DefaultOptions())
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		leases := queue.NewLeases(f.db.DB)
		catchUp := func() int {
			t.Helper()
			queued, err := finding.NewSweeper(f.db, work, quiet, "one").CatchUpOnce(ctx, leases)
			if err != nil {
				t.Fatal(err)
			}
			lapse(t, f)
			return queued
		}

		if n := catchUp(); n != 0 {
			t.Errorf("the catch-up queued %d sweeps where no rule is written", n)
		}
		who := f.planner(t, access.PublicTriage, access.Assigner)
		if _, err := f.store.AddReportRule(ctx, who, f.productID, f.team(t, "intake"),
			"reports to intake"); err != nil {
			t.Fatal(err)
		}
		if n := catchUp(); n != 0 {
			t.Errorf("the catch-up queued %d sweeps where the one rule places reports", n)
		}
		rule := f.ruled(t)
		if err := f.store.RetireRule(ctx, who, f.productID, rule.ID); err != nil {
			t.Fatal(err)
		}
		if n := catchUp(); n != 0 {
			t.Errorf("the catch-up queued %d sweeps where the one rule placing findings is retired", n)
		}
		f.ruled(t)
		if n := catchUp(); n != 1 {
			t.Errorf("the catch-up queued %d sweeps for one ruled product, want one", n)
		}
	})
}

func TestTheCatchUpRunsOnceADayOnWhicheverReplicaAsks(t *testing.T) {
	// One replica runs it a day: every replica asking would queue one sweep
	// per product per replica, and the holder asking again on its next tick
	// would queue one every few minutes. A holder that stops without running
	// it again leaves it to the next replica asking once the day is up.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		work := queue.New(f.db, queue.DefaultOptions())
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		leases := queue.NewLeases(f.db.DB)
		catchUp := func(replica string) int {
			t.Helper()
			queued, err := finding.NewSweeper(f.db, work, quiet, replica).CatchUpOnce(ctx, leases)
			if err != nil {
				t.Fatal(err)
			}
			return queued
		}

		// The same rule in a second product, written as a row: the pass reads
		// rules, and the checks a rule passes on its way in are not its
		// subject.
		f.ruled(t)
		other, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "edge", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		again := *f.ruled(t)
		again.ID, again.ProductID = 0, other.ID
		if _, err := f.db.DB.NewInsert().Model(&again).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		if n := catchUp("one"); n != 2 {
			t.Fatalf("the catch-up queued %d sweeps for two ruled products, want two", n)
		}
		if n := catchUp("two"); n != 0 {
			t.Errorf("a second replica queued %d sweeps within a day of the first", n)
		}
		if n := catchUp("one"); n != 0 {
			t.Errorf("the replica that ran the catch-up queued %d sweeps again within the day", n)
		}

		// Replica one is gone and the day is up.
		lapse(t, f)
		if n := catchUp("two"); n != 2 {
			t.Errorf("a second replica queued %d sweeps once the day was up, want two", n)
		}
	})
}

func TestAFullQueueStopsTheCatchUpAndKeepsTheDay(t *testing.T) {
	// A queue refusing work stops the pass where it is, and the lease is kept
	// so the rest waits a day rather than adding to a queue that refuses.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.ruled(t)
		opts := queue.DefaultOptions()
		opts.MaxBacklog = 1
		work := queue.New(f.db, opts)
		if _, err := work.Add(ctx, queue.AssignmentSweep, "somebody else's product"); err != nil {
			t.Fatal(err)
		}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		leases := queue.NewLeases(f.db.DB)
		queued, err := finding.NewSweeper(f.db, work, quiet, "one").CatchUpOnce(ctx, leases)
		if err != nil || queued != 0 {
			t.Fatalf("a catch-up against a full queue answered %d, %v; want none queued and no error", queued, err)
		}
		if mine, err := leases.TakeLapsed(ctx, finding.CatchUpLease, "two", time.Hour); err != nil || mine {
			t.Errorf("another replica took the catch-up's lease after a full queue stopped it: %v (%v)", mine, err)
		}
	})
}

func TestAFailedCatchUpHandsTheLeaseBack(t *testing.T) {
	// Any failure but a full queue is tried again on the next tick, on any
	// replica, rather than a day later.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.ruled(t)
		broken := queue.New(dbtest.Closed(t), queue.DefaultOptions())
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		leases := queue.NewLeases(f.db.DB)
		if _, err := finding.NewSweeper(f.db, broken, quiet, "one").CatchUpOnce(ctx, leases); err == nil ||
			errors.Is(err, queue.ErrBacklogFull) {
			t.Fatalf("a catch-up whose queue fails answered %v, want the failure", err)
		}
		if mine, err := leases.TakeLapsed(ctx, finding.CatchUpLease, "two", time.Hour); err != nil || !mine {
			t.Errorf("another replica could not take the lease after the catch-up failed: %v (%v)", mine, err)
		}
	})
}

func TestASweepWhoseRestCannotBeQueuedIsTriedAgain(t *testing.T) {
	// A full batch queues the rest of the estate before the job is settled,
	// and a failure to queue it is the job's own failure: settled as done, the
	// rest of the estate would stay unplaced with nothing reporting it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.ruled(t)
		// Two findings beneath the rule, opened with no sweep queued, and a
		// batch of one, so the sweep fills its batch.
		if _, err := f.store.Apply(ctx, f.build, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := setting.NewStore(f.db.DB).Change(ctx, setting.AssignmentBatch, "1"); err != nil {
			t.Fatal(err)
		}
		work := queue.New(f.db, queue.DefaultOptions())
		job, err := work.Add(ctx, queue.AssignmentSweep, strconv.FormatInt(f.productID, 10))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := work.Add(ctx, queue.AssignmentSweep, "somebody else's product"); err != nil {
			t.Fatal(err)
		}
		// One sweep waiting fills the queue once this one is claimed.
		if _, _, err := setting.NewStore(f.db.DB).Change(ctx, setting.QueueBacklog, "1"); err != nil {
			t.Fatal(err)
		}

		sweeper := finding.NewSweeper(f.db, work, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
		claimed, placed, err := sweeper.Once(ctx)
		if !claimed || placed != 1 || !errors.Is(err, queue.ErrBacklogFull) {
			t.Fatalf("a sweep whose rest could not be queued answered %v, %d, %v", claimed, placed, err)
		}
		var held queue.Job
		if err := f.db.DB.NewSelect().Model(&held).Where(`"id" = ?`, job.ID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if held.State != queue.Pending || held.LastError == nil ||
			!strings.Contains(*held.LastError, "queue the rest of the assignment sweep") {
			t.Errorf("the sweep is %s with %v, want it waiting to be tried again", held.State, held.LastError)
		}
	})
}
