// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// closedAt is the one finding closed at the occurrence under a consumer.
func (f *fixture) closedAt(t *testing.T, consumer graph.Described) finding.Finding {
	t.Helper()
	want := finding.OccurrenceIdentity(libnl.Name, consumer.Name)
	var got []finding.Finding
	for _, row := range f.closedRows(t) {
		if row.OccurrenceIdentity == want {
			got = append(got, row)
		}
	}
	if len(got) != 1 {
		t.Fatalf("%d findings closed under %s, want 1", len(got), consumer.Name)
	}
	return got[0]
}

func TestAnUpgradeUnderOneConsumerIsAnUpgradeThoughAnotherKeepsTheOldVersion(t *testing.T) {
	// The library moves to a fixed version under one consumer and stays where
	// it was under the other. A finding is the library at an occurrence, so
	// the occurrence that moved was upgraded; the old version held elsewhere
	// says nothing about it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{swss, teamd, libnl, libnlNew},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss},
				{Parent: root, Child: teamd},
				{Parent: swss, Child: libnlNew},
				{Parent: teamd, Child: libnl},
			},
		})
		applied, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Closed != 1 || applied.Unexplained != 0 {
			t.Errorf("closed %d, %d unexplained; want the one occurrence that moved closed, none unexplained",
				applied.Closed, applied.Unexplained)
		}
		if row := f.closedAt(t, swss); row.ClosedBecause != finding.Upgraded || row.MovedTo != "3.9.0" {
			t.Errorf("closed because %q moving to %q, want %q to 3.9.0",
				row.ClosedBecause, row.MovedTo, finding.Upgraded)
		}
	})
}

func TestAConsumerLeavingClosesItsOccurrenceAsRemovedThoughTheComponentStays(t *testing.T) {
	// The consumer leaves the build and the library stays under the other.
	// What pulled the library in at that occurrence is gone, which explains
	// the closure; the library's presence elsewhere does not make it a fault.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{teamd, libnl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: teamd},
				{Parent: teamd, Child: libnl},
			},
		})
		applied, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Closed != 1 || applied.Unexplained != 0 {
			t.Errorf("closed %d, %d unexplained; want the departed consumer's occurrence closed, none unexplained",
				applied.Closed, applied.Unexplained)
		}
		if row := f.closedAt(t, swss); row.ClosedBecause != finding.Removed || row.MovedTo != "" {
			t.Errorf("closed because %q moving to %q, want %q", row.ClosedBecause, row.MovedTo, finding.Removed)
		}
	})
}

func TestAConsumerDroppingTheComponentClosesItsOccurrenceAsRemoved(t *testing.T) {
	// The consumer stays and no longer pulls the library in, which the other
	// still does. The library left that occurrence.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{swss, teamd, libnl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss},
				{Parent: root, Child: teamd},
				{Parent: teamd, Child: libnl},
			},
		})
		applied, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Unexplained != 0 {
			t.Errorf("%d unexplained, want none", applied.Unexplained)
		}
		if row := f.closedAt(t, swss); row.ClosedBecause != finding.Removed {
			t.Errorf("closed because %q, want %q", row.ClosedBecause, finding.Removed)
		}
	})
}

// reshipped opens the one finding on libnl and closes whatever the next graph
// no longer holds, returning what the closing scan applied.
func (f *fixture) reshipped(t *testing.T, before, after graph.Snapshot,
	still ...finding.Reported) finding.Applied {
	t.Helper()
	f.shipped(t, before)
	if _, err := f.store.Apply(t.Context(), f.build, f.run(t),
		[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
		t.Fatal(err)
	}
	f.shipped(t, after)
	applied, err := f.store.Apply(t.Context(), f.build, f.run(t), still)
	if err != nil {
		t.Fatal(err)
	}
	return applied
}

func TestAConsumerLeavingWithTheComponentUpgradedElsewhereIsAnUpgrade(t *testing.T) {
	// The consumer leaves and the library ships at a newer version under the
	// product. A release note saying the library no longer ships would be
	// false.
	each(t, func(t *testing.T, f *fixture) {
		f.reshipped(t, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{swss, libnl},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: swss, Child: libnl}},
		}, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{teamd, libnlNew},
			Dependencies: []graph.Dependency{{Parent: root, Child: teamd}, {Parent: root, Child: libnlNew}},
		})
		if row := f.closedAt(t, swss); row.ClosedBecause != finding.Upgraded || row.MovedTo != "3.9.0" {
			t.Errorf("closed because %q moving to %q, want %q to 3.9.0",
				row.ClosedBecause, row.MovedTo, finding.Upgraded)
		}
	})
}

func TestOccurrencesClosingInOneScanAgreeOnAnUpgradeWhereAConsumerLeft(t *testing.T) {
	// One consumer moves the library to a newer version and the other, which
	// kept the old one, leaves. The issue closes at both occurrences in one
	// scan, so a release note reading the later row says the same whichever
	// it reads.
	each(t, func(t *testing.T, f *fixture) {
		applied := f.reshipped(t, twoConsumers(), graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{swss, libnlNew},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: swss, Child: libnlNew}},
		})
		if applied.Closed != 2 {
			t.Errorf("closed %d, want both occurrences", applied.Closed)
		}
		for _, consumer := range []graph.Described{swss, teamd} {
			if row := f.closedAt(t, consumer); row.ClosedBecause != finding.Upgraded || row.MovedTo != "3.9.0" {
				t.Errorf("under %s closed because %q moving to %q, want %q to 3.9.0",
					consumer.Name, row.ClosedBecause, row.MovedTo, finding.Upgraded)
			}
		}
	})
}

func TestAConsumerDroppingTheComponentUpgradedElsewhereIsAnUpgrade(t *testing.T) {
	// One consumer moves the library to a newer version and the other stays
	// and no longer pulls it in. The old version is gone from the build.
	each(t, func(t *testing.T, f *fixture) {
		f.reshipped(t, twoConsumers(), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{swss, teamd, libnlNew},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss},
				{Parent: root, Child: teamd},
				{Parent: swss, Child: libnlNew},
			},
		})
		if row := f.closedAt(t, teamd); row.ClosedBecause != finding.Upgraded || row.MovedTo != "3.9.0" {
			t.Errorf("closed because %q moving to %q, want %q to 3.9.0",
				row.ClosedBecause, row.MovedTo, finding.Upgraded)
		}
	})
}

func TestAnEdgeTheProducerStopsNamingIsUnexplained(t *testing.T) {
	// The consumer and the library both still ship, the library now directly
	// under the product. Nothing changed but what the producer wrote, which is
	// the fault the warning exists for.
	each(t, func(t *testing.T, f *fixture) {
		applied := f.reshipped(t, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{swss, libnl},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: swss, Child: libnl}},
		}, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{swss, libnl},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: root, Child: libnl}},
		}, found("CVE-2026-1", libnl))
		if applied.Unexplained != 1 {
			t.Errorf("%d unexplained, want the occurrence whose edge went unnamed", applied.Unexplained)
		}
		if row := f.closedAt(t, swss); row.ClosedBecause != finding.Unexplained {
			t.Errorf("closed because %q, want %q", row.ClosedBecause, finding.Unexplained)
		}
	})
}

func TestAComponentThatWasItsOwnConsumerIsRemovedThoughUnderTheProduct(t *testing.T) {
	// An occurrence under the component itself, as v0.12.0 recorded one for a
	// component listed as depending on itself, places nothing now. Its finding
	// closes as removed while the component sits under the product.
	each(t, func(t *testing.T, f *fixture) {
		alone := graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{swss, libnl},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: swss, Child: libnl}},
		}
		f.shipped(t, alone)
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"consumer_id" = "component_id"`).
			Set(`"occurrence_identity" = ?`, finding.OccurrenceIdentity(libnl.Name, libnl.Name)).
			Where(`"build_id" = ?`, f.build).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{swss, libnl},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: root, Child: libnl}},
		})
		applied, err := f.store.Apply(t.Context(), f.build, f.run(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Unexplained != 0 {
			t.Errorf("%d unexplained, want none", applied.Unexplained)
		}
		if row := f.closedAt(t, libnl); row.ClosedBecause != finding.Removed {
			t.Errorf("closed because %q, want %q", row.ClosedBecause, finding.Removed)
		}
	})
}

func TestTheSameComponentUnderItsConsumerIsUnexplainedBeforeAnotherVersionThere(t *testing.T) {
	// The consumer pulls in the library at the old version and the new. The
	// scanner falling silent on the old one is no upgrade.
	each(t, func(t *testing.T, f *fixture) {
		both := graph.Snapshot{Root: root, Components: []graph.Described{swss, libnl, libnlNew},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss},
				{Parent: swss, Child: libnl}, {Parent: swss, Child: libnlNew}}}
		applied := f.reshipped(t, both, both)
		if applied.Unexplained != 1 {
			t.Errorf("%d unexplained, want the one the scanner fell silent on", applied.Unexplained)
		}
		if row := f.closedAt(t, swss); row.ClosedBecause != finding.Unexplained {
			t.Errorf("closed because %q, want %q", row.ClosedBecause, finding.Unexplained)
		}
	})
}
