// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

var (
	kernel     = at("linux-image-6.12.94+deb13-sonic-amd64-unsigned", "6.12.94-1")
	kernelNew  = at("linux-image-6.12.95+deb13-sonic-amd64-unsigned", "6.12.95-1")
	opennsl    = at("opennsl-modules", "15.2.0")
	opennslMid = at("opennsl-modules", "15.2.1")
	opennslNew = at("opennsl-modules", "16.0.0")
)

const kernelIssue = "CVE-2026-74279"

// pulling is a build whose kernel each consumer given pulls in.
func pulling(child graph.Described, consumers ...graph.Described) graph.Snapshot {
	snap := graph.Snapshot{Root: root, Components: []graph.Described{child}}
	for _, consumer := range consumers {
		snap.Components = append(snap.Components, consumer)
		snap.Dependencies = append(snap.Dependencies,
			graph.Dependency{Parent: root, Child: consumer},
			graph.Dependency{Parent: consumer, Child: child})
	}
	return snap
}

// componentOf is the component row a package at a version was stored as.
func (f *fixture) componentOf(t *testing.T, d graph.Described) int64 {
	t.Helper()
	var id int64
	if err := f.db.DB.NewSelect().Model((*graph.Component)(nil)).Column("id").
		Where(`"name" = ?`, d.Name).Where(`"version" = ?`, d.Version).
		Scan(t.Context(), &id); err != nil {
		t.Fatalf("read %s@%s: %v", d.Name, d.Version, err)
	}
	return id
}

// under is the finding row of the build under a consumer, open or closed.
func (f *fixture) under(t *testing.T, consumer graph.Described) []finding.Finding {
	t.Helper()
	id := f.componentOf(t, consumer)
	var out []finding.Finding
	for _, row := range f.every(t) {
		if row.ConsumerID != nil && *row.ConsumerID == id {
			out = append(out, row)
		}
	}
	return out
}

func TestAConsumersVersionMovingKeepsTheFindingBeneathItOpen(t *testing.T) {
	// The kernel sits under opennsl-modules, which moves to a new version while
	// the kernel does not. The finding is the kernel at that occurrence, so it
	// stays the one open row: its opening, deadline and assignment describe
	// the kernel's exposure, which did not change.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, pulling(kernel, opennsl))
		first := f.run(t)
		f.backdate(t, first, 10*24*time.Hour)
		if _, err := f.store.Apply(ctx, f.build, first, []finding.Reported{found(kernelIssue, kernel)}); err != nil {
			t.Fatal(err)
		}
		opened := f.open(t)
		if len(opened) != 1 || opened[0].DueAt == nil {
			t.Fatalf("the first scan opened %+v, want one finding with a deadline", opened)
		}
		assigner := f.holding(t, access.PublicTriage, access.Assigner)
		if moved, _, err := f.store.Assign(ctx, assigner, f.build, opened[0].VulnerabilityID,
			opened[0].ComponentID, ptr(int64(7)), nil); err != nil || moved != 1 {
			t.Fatalf("assigning the finding moved %d: %v", moved, err)
		}
		before := f.open(t)[0]

		f.shipped(t, pulling(kernel, opennslNew))
		applied := f.applied(t, found(kernelIssue, kernel))
		if applied.Opened != 0 || applied.Closed != 0 {
			t.Errorf("the consumer's bump opened %d and closed %d, want neither", applied.Opened, applied.Closed)
		}
		rows := f.every(t)
		if len(rows) != 1 {
			t.Fatalf("the build holds %d rows after the consumer's bump, want the one", len(rows))
		}
		after := rows[0]
		if after.ID != before.ID || after.ClosedAt != nil {
			t.Fatalf("row %d closed at %v, want row %d open", after.ID, after.ClosedAt, before.ID)
		}
		if !after.OpenedAt.Equal(before.OpenedAt) {
			t.Errorf("opened at %v, want %v", after.OpenedAt, before.OpenedAt)
		}
		if after.DueAt == nil || !after.DueAt.Equal(*before.DueAt) {
			t.Errorf("due at %v, want %v", after.DueAt, *before.DueAt)
		}
		if after.AssignedTo == nil || *after.AssignedTo != 7 {
			t.Errorf("held by %v, want 7", after.AssignedTo)
		}
		if want := f.componentOf(t, opennslNew); after.ConsumerID == nil || *after.ConsumerID != want {
			t.Errorf("under consumer %v, want the new version's %d", after.ConsumerID, want)
		}
		if after.ArrivedFrom != "" {
			t.Errorf("arrived from %q, want nothing, since the kernel did not move", after.ArrivedFrom)
		}
	})
}

func TestAComponentMovingWithItsConsumerSupersedesItsFinding(t *testing.T) {
	// The kernel moves with the consumer that pulls it in. The issue at the
	// new kernel is a new finding, and the one before it is superseded.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, pulling(kernel, opennsl))
		f.applied(t, found(kernelIssue, kernel))
		f.shipped(t, pulling(kernelNew, opennslNew))
		applied := f.applied(t, found(kernelIssue, kernelNew))
		if applied.Opened != 1 || applied.Closed != 1 {
			t.Fatalf("opened %d and closed %d, want one of each", applied.Opened, applied.Closed)
		}
		old := f.under(t, opennsl)
		if len(old) != 1 || old[0].ClosedBecause != finding.Superseded {
			t.Errorf("the finding under the old consumer is %+v, want one closed superseded", old)
		}
		now := f.under(t, opennslNew)
		if len(now) != 1 || now[0].ClosedAt != nil || now[0].ArrivedFrom != kernel.Version {
			t.Errorf("the finding under the new consumer is %+v, want one open arrived from %s",
				now, kernel.Version)
		}
	})
}

func TestAConsumerAtASecondVersionLeavesTheHeldFindingOnItsOwnConsumer(t *testing.T) {
	// One consumer name at two versions is two rows at one occurrence. The
	// version already held keeps its row, and the second opens its own,
	// though the second has the lower identifier.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, pulling(kernel, opennslMid))
		f.shipped(t, pulling(kernel, opennslNew))
		f.applied(t, found(kernelIssue, kernel))
		held := f.open(t)[0]
		if f.componentOf(t, opennslMid) > f.componentOf(t, opennslNew) {
			t.Fatal("the version arriving second does not have the lower identifier, so this checks nothing")
		}
		f.shipped(t, pulling(kernel, opennslMid, opennslNew))
		applied := f.applied(t, found(kernelIssue, kernel))
		if applied.Opened != 1 || applied.Closed != 0 {
			t.Errorf("opened %d and closed %d, want one opened", applied.Opened, applied.Closed)
		}
		if rows := f.under(t, opennslNew); len(rows) != 1 || rows[0].ID != held.ID || rows[0].ClosedAt != nil {
			t.Errorf("under the held version: %+v, want row %d open", rows, held.ID)
		}
		if rows := f.under(t, opennslMid); len(rows) != 1 || rows[0].ClosedAt != nil {
			t.Errorf("under the second version: %+v, want one open row", rows)
		}
	})
}

func TestAConsumerAtNewVersionsContinuesTheHeldFindingUnderTheLowestConsumer(t *testing.T) {
	// The one version held is gone and two new ones arrive. The held row
	// continues under the consumer with the lower identifier, and the other
	// opens.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, pulling(kernel, opennsl))
		f.applied(t, found(kernelIssue, kernel))
		held := f.open(t)[0]
		f.shipped(t, pulling(kernel, opennslMid, opennslNew))
		applied := f.applied(t, found(kernelIssue, kernel))
		if applied.Opened != 1 || applied.Closed != 0 {
			t.Errorf("opened %d and closed %d, want one opened", applied.Opened, applied.Closed)
		}
		lowest := min(f.componentOf(t, opennslMid), f.componentOf(t, opennslNew))
		for _, row := range f.open(t) {
			if continued := row.ID == held.ID; continued != (*row.ConsumerID == lowest) {
				t.Errorf("row %d under consumer %d: continued %v, want the held row %d under %d",
					row.ID, *row.ConsumerID, continued, held.ID, lowest)
			}
		}
	})
}

func TestAConsumerLeftAtOneOfTwoVersionsKeepsTheOtherFindingAndClosesItsOwn(t *testing.T) {
	// Two versions of one consumer hold two rows at one occurrence, and one of
	// the versions leaves. The row on the version that stays is unchanged; the
	// other closes for what explains it at its occurrence, and is not
	// superseded, since no version of the kernel moved.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, pulling(kernel, opennsl, opennslNew))
		f.applied(t, found(kernelIssue, kernel))
		staying := f.under(t, opennslNew)[0]
		f.shipped(t, pulling(kernel, opennslNew))
		applied := f.applied(t, found(kernelIssue, kernel))
		if applied.Opened != 0 || applied.Closed != 1 {
			t.Errorf("opened %d and closed %d, want one closed", applied.Opened, applied.Closed)
		}
		if rows := f.under(t, opennslNew); len(rows) != 1 || rows[0].ID != staying.ID || rows[0].ClosedAt != nil {
			t.Errorf("under the version that stays: %+v, want row %d open", rows, staying.ID)
		}
		if rows := f.under(t, opennsl); len(rows) != 1 || rows[0].ClosedBecause != finding.Unexplained {
			t.Errorf("under the version that left: %+v, want one closed unexplained", rows)
		}
	})
}

func TestTwoHeldFindingsUnderOneNewConsumerContinueTheOneOpenedFirst(t *testing.T) {
	// Two versions of one consumer hold two rows, and both give way to a third.
	// The row with the lower identifier continues under it; the other closes,
	// not superseded.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, pulling(kernel, opennsl, opennslMid))
		f.applied(t, found(kernelIssue, kernel))
		ids := []int64{}
		for _, row := range f.open(t) {
			ids = append(ids, row.ID)
		}
		first := slices.Min(ids)
		f.shipped(t, pulling(kernel, opennslNew))
		applied := f.applied(t, found(kernelIssue, kernel))
		if applied.Opened != 0 || applied.Closed != 1 {
			t.Errorf("opened %d and closed %d, want one closed", applied.Opened, applied.Closed)
		}
		for _, row := range f.every(t) {
			if row.ID == first {
				if row.ClosedAt != nil || *row.ConsumerID != f.componentOf(t, opennslNew) {
					t.Errorf("the row opened first is %+v, want it open under the new version", row)
				}
				continue
			}
			if row.ClosedBecause != finding.Unexplained {
				t.Errorf("the other row closed because %q, want %q", row.ClosedBecause, finding.Unexplained)
			}
		}
	})
}

func TestADecisionOnAConsumersOldVersionLapsesAsTheFindingContinues(t *testing.T) {
	// A decision is keyed on the upstream versions of the component and of
	// what pulls it in. The finding continuing under the consumer's new
	// version leaves the decision keyed on the old one, and the sweep lapses
	// it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, pulling(kernel, opennsl))
		f.applied(t, found(kernelIssue, kernel))
		row := f.open(t)[0]
		f.decidedAt(t, f.somebodyElse(t), row, "approved", kernel.Version, opennsl.Version, "k")
		sweep := triage.NewStore(f.db.DB)
		if lapsed, err := sweep.Lapse(ctx, f.build); err != nil || lapsed.Rows != 0 {
			t.Fatalf("a sweep before the bump lapsed %d (%v), want none", lapsed.Rows, err)
		}

		f.shipped(t, pulling(kernel, opennslNew))
		f.applied(t, found(kernelIssue, kernel))
		lapsed, err := sweep.Lapse(ctx, f.build)
		if err != nil {
			t.Fatal(err)
		}
		if lapsed.Rows != 1 {
			t.Errorf("the sweep after the consumer's bump lapsed %d, want the one decision", lapsed.Rows)
		}
	})
}
