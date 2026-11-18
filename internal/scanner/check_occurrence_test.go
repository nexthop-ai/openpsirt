// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

func TestACheckExplainsAnOccurrenceByWhatItsConsumerPullsInNow(t *testing.T) {
	// The replacement moves the library under one consumer and keeps it under
	// the other. The check records the issue at the occurrence that moved,
	// closed as upgraded to the version that consumer now pulls in, though
	// the replaced version is still in the build.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		teamd := at("teamd", "1.31")
		f := replacedInventoryOf(t, w, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{swss, teamd, libnl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss}, {Parent: root, Child: teamd},
				{Parent: swss, Child: libnl}, {Parent: teamd, Child: libnl},
			},
		}, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{swss, teamd, libnl, libnlFixed},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss}, {Parent: root, Child: teamd},
				{Parent: swss, Child: libnlFixed}, {Parent: teamd, Child: libnl},
			},
		})
		f.published(t, "CVE-2026-0007", f.arrived.Add(24*time.Hour))
		checking := f.check(t, &dated{at: time.Now().UTC(),
			reported: []finding.Reported{reportAt("CVE-2026-0007", libnl)}})
		if checking == nil {
			t.Fatal("a check was waiting and nothing was done")
		}
		var rows []finding.Finding
		if err := f.db.NewSelect().Model(&rows).Where(`"build_id" = ?`, f.build).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		want := finding.OccurrenceIdentity(libnl.Name, swss.Name)
		var got []finding.Finding
		for _, row := range rows {
			if row.OccurrenceIdentity == want {
				got = append(got, row)
			}
		}
		if len(got) != 1 {
			t.Fatalf("%d findings recorded under %s, want 1", len(got), swss.Name)
		}
		if got[0].ClosedBecause != finding.Upgraded || got[0].MovedTo != "3.9.0" {
			t.Errorf("closed because %q moving to %q, want %q to 3.9.0",
				got[0].ClosedBecause, got[0].MovedTo, finding.Upgraded)
		}
	})
}
