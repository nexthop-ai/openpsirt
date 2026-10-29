// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
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
