// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
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
	// other closes as superseded, the issue still open at the occurrence.
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
		if rows := f.under(t, opennsl); len(rows) != 1 || rows[0].ClosedBecause != finding.Superseded {
			t.Errorf("under the version that left: %+v, want one closed superseded", rows)
		}
	})
}

func TestTwoHeldFindingsUnderOneNewConsumerContinueTheOneOpenedFirst(t *testing.T) {
	// Two versions of one consumer hold two rows, and both give way to a third.
	// The row with the lower identifier continues under it; the other closes as
	// superseded.
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
			if row.ClosedBecause != finding.Superseded {
				t.Errorf("the other row closed because %q, want %q", row.ClosedBecause, finding.Superseded)
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

func TestABurndownCountsADismissalOverTheConsumerVersionItWasKeyedOn(t *testing.T) {
	// A dismissal keyed on opennsl-modules 15.2.0 stands over the kernel until
	// the consumer moves and the dismissal lapses. The finding continues under
	// the new version, and while it sat under the old one the issue was
	// dismissed.
	each(t, func(t *testing.T, f *fixture) {
		f.scannedAt(t, pulling(kernel, opennsl), ago(20), found(kernelIssue, kernel))
		agreed, lapsed := ago(15), ago(5)
		f.dismissed(t, dismissal{issue: kernelIssue, proposed: agreed, agreed: &agreed, ended: &lapsed,
			state: "lapsed"})
		f.scannedAt(t, pulling(kernel, opennslNew), lapsed, found(kernelIssue, kernel))
		if rows := f.every(t); len(rows) != 1 {
			t.Fatalf("the build holds %d rows, want the one finding continued", len(rows))
		}

		b := f.burndown(t, "", finding.Within{})
		if p := pointOn(b, ago(10)); p.Left != 0 {
			t.Errorf("while the dismissal stood %d were left, want none", p.Left)
		}
		if p := pointOn(b, lapsed); p.Returned != 1 {
			t.Errorf("the day it lapsed says %d returned, want one", p.Returned)
		}
		if got := burnedOver(b); got.left != 1 || got.dismissed != 0 {
			t.Errorf("counted %+v, want nothing dismissed and one left", got)
		}
	})
}

func TestABurndownCountsNoDismissalOnAConsumerVersionTheFindingNeverSatUnder(t *testing.T) {
	// The kernel has only ever sat under opennsl-modules 16.0.0. A dismissal
	// keyed on 15.2.0 answers another build's finding, never this one.
	each(t, func(t *testing.T, f *fixture) {
		f.scannedAt(t, pulling(kernel, opennslNew), ago(20), found(kernelIssue, kernel))
		row := f.open(t)[0]
		by := f.somebodyElse(t)
		component, consumer := kernel.Version, opennsl.Version
		f.decision(t, decisionRow{
			By: by, Decision: decisionSaying(t, f.db, by, finding.OutcomeNotApplicable),
			Issue: row.VulnerabilityID, Occurrence: row.OccurrenceIdentity, State: "approved",
			Unreviewed: true, Component: &component, Consumer: &consumer, ProposedAt: ago(15), Key: "k",
		})

		b := f.burndown(t, "", finding.Within{})
		if p := pointOn(b, ago(10)); p.Left != 1 {
			t.Errorf("%d left, want the finding no dismissal covers", p.Left)
		}
	})
}

func TestADismissalStillStandingElsewhereStopsAnsweringAFindingWhoseConsumerMoved(t *testing.T) {
	// A dismissal keyed on opennsl-modules 15.2.0 stays in force while another
	// build ships that version. Here the consumer moves on, so from that run
	// the finding is the burndown's to count again.
	each(t, func(t *testing.T, f *fixture) {
		f.scannedAt(t, pulling(kernel, opennsl), ago(20), found(kernelIssue, kernel))
		row := f.open(t)[0]
		by := f.somebodyElse(t)
		component, consumer := kernel.Version, opennsl.Version
		f.decision(t, decisionRow{
			By: by, Decision: decisionSaying(t, f.db, by, finding.OutcomeNotApplicable),
			Issue: row.VulnerabilityID, Occurrence: row.OccurrenceIdentity, State: "approved",
			Unreviewed: true, Component: &component, Consumer: &consumer, ProposedAt: ago(15), Key: "k",
		})
		moved := ago(5)
		f.scannedAt(t, pulling(kernel, opennslNew), moved, found(kernelIssue, kernel))

		b := f.burndown(t, "", finding.Within{})
		if p := pointOn(b, ago(10)); p.Left != 0 {
			t.Errorf("while it sat under the version decided about %d were left, want none", p.Left)
		}
		if got := burnedOver(b); got.left != 1 {
			t.Errorf("counted %+v, want one left once the consumer moved", got)
		}
	})
}

func TestAComponentMovingUnderOneOfTwoConsumerVersionsSupersedesItsFinding(t *testing.T) {
	// Two versions of one consumer pull in libnl 3.7.0, and the newer one moves
	// to libnl 3.9.0. The issue is still open at the occurrence on 3.7.0 under
	// the other, and the row under the newer consumer is superseded by the one
	// at 3.9.0, which arrived from 3.7.0.
	each(t, func(t *testing.T, f *fixture) {
		nmod, nmodNew := at("nmod", "1.0"), at("nmod", "2.0")
		f.shipped(t, pulling(libnl, nmod, nmodNew))
		f.applied(t, found("CVE-2026-1", libnl))
		f.shipped(t, graph.Snapshot{
			Root: root, Components: []graph.Described{nmod, nmodNew, libnl, libnlNew},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: nmod}, {Parent: nmod, Child: libnl},
				{Parent: root, Child: nmodNew}, {Parent: nmodNew, Child: libnlNew},
			},
		})
		applied := f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-1", libnlNew))
		if applied.Opened != 1 || applied.Closed != 1 {
			t.Errorf("opened %d and closed %d, want one of each", applied.Opened, applied.Closed)
		}
		var closed, opened []finding.Finding
		for _, row := range f.under(t, nmodNew) {
			if row.ClosedAt != nil {
				closed = append(closed, row)
			} else {
				opened = append(opened, row)
			}
		}
		if len(closed) != 1 || closed[0].ClosedBecause != finding.Superseded {
			t.Errorf("closed under the newer consumer: %+v, want one superseded", closed)
		}
		if len(opened) != 1 || opened[0].ArrivedFrom != libnl.Version {
			t.Errorf("open under the newer consumer: %+v, want one arrived from %s", opened, libnl.Version)
		}
	})
}

func TestAFindingPatchedAsItsConsumerMovesClosesOnceUnderTheNewConsumer(t *testing.T) {
	// The build declares the kernel patched in the scan that moves its consumer.
	// The held finding closes as patched under the new consumer, and no second
	// row records the patch.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, pulling(kernel, opennsl))
		f.applied(t, found(kernelIssue, kernel))
		f.shipped(t, pulling(kernel, opennslNew))
		if _, err := world.RecordClaims(t.Context(), f.db, f.build, f.lastScan, []sbom.Suppression{
			aClaim(kernelIssue, sbom.AlreadyFixed, kernel, sbom.FromPedigree),
		}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		f.closesOnceUnderTheNewConsumer(t, finding.Patched, found(kernelIssue, kernel))
	})
}

func TestAFindingTheRecordExcludesAsItsConsumerMovesClosesOnceUnderTheNewConsumer(t *testing.T) {
	// The issue's record excludes the kernel's release in the scan that moves
	// its consumer. The held finding closes as unaffected under the new
	// consumer, and no second row records it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, pulling(kernel, opennsl))
		f.applied(t, found(kernelIssue, kernel))
		f.shipped(t, pulling(kernel, opennslNew))
		excluded := found(kernelIssue, kernel)
		excluded.Unaffected = recordSays
		f.closesOnceUnderTheNewConsumer(t, finding.Unaffected, excluded)
	})
}

func TestAFindingASupplierAnswersAsItsConsumerMovesClosesOnceUnderTheNewConsumer(t *testing.T) {
	// Acme's statement covers zlib inside Y 4.2, and the build moves Y from 4.3
	// to 4.2. The held finding closes as disclaimed under 4.2, and no second
	// row records it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, beside(acmeYNew))
		f.acmeSays(t)
		f.reported(t, found(inside, zlib))
		held := f.under(t, acmeYNew)
		if len(held) != 1 || held[0].ClosedAt != nil {
			t.Fatalf("under Y 4.3: %+v, want one open row", held)
		}
		f.shipped(t, beside(acmeY))
		applied, _ := f.reported(t, found(inside, zlib))
		if applied.Opened != 0 || applied.Closed != 1 || applied.Disclaimed != 1 {
			t.Errorf("opened %d, closed %d, disclaimed %d; want one closed as disclaimed",
				applied.Opened, applied.Closed, applied.Disclaimed)
		}
		rows := f.under(t, acmeY)
		if len(rows) != 1 || rows[0].ID != held[0].ID || rows[0].ClosedBecause != finding.Disclaimed {
			t.Errorf("under Y 4.2: %+v, want row %d closed as disclaimed", rows, held[0].ID)
		}
		if again, _ := f.reported(t, found(inside, zlib)); !changedNothing(again) {
			t.Errorf("re-scanning wrote %+v", again)
		}
	})
}

// closesOnceUnderTheNewConsumer applies a scan reporting what is given under
// opennsl-modules 16.0.0, and holds the one finding held under 15.2.0 to have
// closed for the reason given under 16.0.0, with nothing else written, then
// and on a rescan.
func (f *fixture) closesOnceUnderTheNewConsumer(t *testing.T, reason finding.Closure, reported finding.Reported) {
	t.Helper()
	held := f.open(t)
	if len(held) != 1 {
		t.Fatalf("%d open before the move, want one", len(held))
	}
	applied := f.applied(t, reported)
	if applied.Opened != 0 || applied.Closed != 1 {
		t.Errorf("opened %d and closed %d, want one closed", applied.Opened, applied.Closed)
	}
	rows := f.every(t)
	if len(rows) != 1 {
		t.Fatalf("the build holds %d rows, want the one finding closed where it continued", len(rows))
	}
	row := rows[0]
	if row.ID != held[0].ID || row.ClosedBecause != reason {
		t.Errorf("row %d closed because %q, want row %d closed as %q", row.ID, row.ClosedBecause,
			held[0].ID, reason)
	}
	if want := f.componentOf(t, opennslNew); row.ConsumerID == nil || *row.ConsumerID != want {
		t.Errorf("closed under consumer %v, want the new version's %d", row.ConsumerID, want)
	}
	if again := f.applied(t, reported); !changedNothing(again) {
		t.Errorf("re-scanning wrote %+v", again)
	}
}

func TestADismissalOnAConsumerVersionAnswersTheFindingOnlyOnceItSitsUnderIt(t *testing.T) {
	// A dismissal keyed on opennsl-modules 16.0.0 was made in another build.
	// This build moves the kernel's consumer to 16.0.0 later, and only from
	// that run is its finding answered.
	each(t, func(t *testing.T, f *fixture) {
		f.scannedAt(t, pulling(kernel, opennsl), ago(20), found(kernelIssue, kernel))
		row := f.open(t)[0]
		by := f.somebodyElse(t)
		component, consumer := kernel.Version, opennslNew.Version
		f.decision(t, decisionRow{
			By: by, Decision: decisionSaying(t, f.db, by, finding.OutcomeNotApplicable),
			Issue: row.VulnerabilityID, Occurrence: row.OccurrenceIdentity, State: "approved",
			Unreviewed: true, Component: &component, Consumer: &consumer, ProposedAt: ago(15), Key: "k",
		})
		f.scannedAt(t, pulling(kernel, opennslNew), ago(5), found(kernelIssue, kernel))

		b := f.burndown(t, "", finding.Within{})
		if p := pointOn(b, ago(10)); p.Left != 1 {
			t.Errorf("under the version decided against, %d left, want the finding", p.Left)
		}
		if got := burnedOver(b); got.left != 0 || got.dismissed != 1 {
			t.Errorf("counted %+v, want it dismissed once it sat under 16.0.0", got)
		}
	})
}
