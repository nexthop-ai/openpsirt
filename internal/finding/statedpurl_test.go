// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The package identifier a build stated is the open version of a rebuilt
// image, the node's own identifier elsewhere, and nothing for a component the
// build no longer ships.
func TestTheStatedIdentifierIsTheOpenImageVersionElseTheNodes(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := inImage(swssImage("master.1-aaa"), libnl)
		first.Components = append(first.Components, teamd)
		first.Dependencies = append(first.Dependencies, graph.Dependency{Parent: root, Child: teamd})
		f.shipped(t, first)
		f.shipped(t, inImage(swssImage("master.2-bbb"), libnl))

		var rows []struct {
			ComponentID int64  `bun:"component_id"`
			Name        string `bun:"name"`
		}
		if err := f.db.DB.NewSelect().
			TableExpr(`"graph_node" AS "n"`).
			Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
			ColumnExpr(`"n"."component_id", "c"."name"`).
			Where(`"n"."build_id" = ?`, f.build).
			Scan(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		components := make([]int64, 0, len(rows))
		byName := map[string]int64{}
		for _, row := range rows {
			components = append(components, row.ComponentID)
			byName[row.Name] = row.ComponentID
		}
		stated, err := finding.StatedPurls(ctx, f.db.DB, f.build, components)
		if err != nil {
			t.Fatal(err)
		}

		if want, got := "pkg:oci/docker-swss@master.2-bbb?arch=amd64", stated[byName["docker-swss"]]; got.String != want {
			t.Errorf("the rebuilt image is stated as %v, want its open version's %s", got, want)
		}
		if want, got := libnl.Purl, stated[byName[libnl.Name]]; got.String != want {
			t.Errorf("libnl is stated as %v, want its node's %s", got, want)
		}
		if got, held := stated[byName[teamd.Name]]; byName[teamd.Name] == 0 || held {
			t.Errorf("teamd, no longer shipped, is stated as %v (held %t), want nothing", got, held)
		}
	})
}
