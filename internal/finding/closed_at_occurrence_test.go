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
