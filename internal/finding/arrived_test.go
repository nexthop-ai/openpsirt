// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// sweeps counts the assignment sweeps waiting.
func (f *fixture) sweeps(t *testing.T) int {
	t.Helper()
	n, err := f.db.DB.NewSelect().Model((*queue.Job)(nil)).
		Where(`"kind" = ?`, queue.AssignmentSweep).
		Where(`"state" = ?`, queue.Pending).
		Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return int(n)
}

// ruled writes a rule placing everything on libnl with a team that reads the
// product, and runs it over what is open, as writing one through the API
// does.
func (f *fixture) ruled(t *testing.T) *finding.AssignmentRule {
	t.Helper()
	ctx := t.Context()
	who := f.planner(t, access.PublicTriage, access.Assigner)
	rule, err := f.store.AddRule(ctx, who, f.productID, f.team(t, "platform"),
		"libnl to platform", "", "libnl-3-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := f.store.ApplyRules(ctx, f.productID, 100); err != nil {
		t.Fatal(err)
	}
	return rule
}

func TestARulePlacesWorkAScanOpensAfterTheRuleWasWritten(t *testing.T) {
	// A rule runs when it is written and when work arrives, so what a later
	// scan opens beneath it is placed as what was open when it was written.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.foundOnLibnl(t)
		f.ruled(t)

		work := queue.New(f.db, queue.DefaultOptions())
		if _, err := f.store.Sweeping(work).Apply(ctx, f.build, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}

		placed, err := finding.NewSweeper(f.db, work,
			slog.New(slog.NewTextHandler(io.Discard, nil)), "test").Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if placed == 0 {
			t.Fatal("nothing was placed after a scan opened work beneath the rule")
		}
		for _, row := range f.open(t) {
			if row.AssignedTo == nil {
				t.Errorf("finding %d on libnl is unheld after the sweep", row.ID)
			}
		}
	})
}

func TestAScanQueuesNoSweepWhereNoRulePlacesWork(t *testing.T) {
	// A deployment with no rules queues nothing per scan, and a retired rule
	// is no rule: queued anyway, every nightly scan of every build would add
	// a sweep that places nothing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		work := queue.New(f.db, queue.DefaultOptions())
		if _, err := f.store.Sweeping(work).Apply(ctx, f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		if n := f.sweeps(t); n != 0 {
			t.Errorf("a product with no rule has %d sweeps queued", n)
		}

		rule := f.ruled(t)
		who := f.planner(t, access.PublicTriage, access.Assigner)
		if err := f.store.RetireRule(ctx, who, f.productID, rule.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Sweeping(work).Apply(ctx, f.build, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		if n := f.sweeps(t); n != 0 {
			t.Errorf("a product whose one rule is retired has %d sweeps queued", n)
		}
	})
}

func TestAFullSweepQueueDoesNotRefuseTheScan(t *testing.T) {
	// Refusing the scan loses what it found; leaving its sweep to the next
	// arrival only delays placing it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.foundOnLibnl(t)
		f.ruled(t)

		full := queue.New(f.db, queue.Options{
			MaxAttempts: 5, MaxBacklog: 1, ClaimTimeout: 30 * time.Minute,
			Heartbeat: 5 * time.Minute, Backoff: 30 * time.Second,
		})
		if _, err := full.Add(ctx, queue.AssignmentSweep, "another product"); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Sweeping(full).Apply(ctx, f.build, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		})
		if err != nil {
			t.Fatalf("a full sweep queue refused the scan: %v", err)
		}
		if applied.Opened == 0 {
			t.Error("the scan opened nothing")
		}
		if n := f.sweeps(t); n != 1 {
			t.Errorf("%d sweeps are queued, want only the one already there", n)
		}
	})
}
