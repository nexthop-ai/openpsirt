// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"database/sql"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The package identifier a build stated is read per row inside a statement and
// as sets for the closed reads of a VEX document, and both name the same one:
// the open version of a rebuilt image, the node's own identifier elsewhere,
// and nothing for a component the build no longer ships.
func TestTheStatedIdentifierIsTheSameReadPerRowOrAsSets(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := inImage(swssImage("master.1-aaa"), libnl)
		first.Components = append(first.Components, teamd)
		first.Dependencies = append(first.Dependencies, graph.Dependency{Parent: root, Child: teamd})
		f.shipped(t, first)
		f.shipped(t, inImage(swssImage("master.2-bbb"), libnl))

		var rows []struct {
			ComponentID int64          `bun:"component_id"`
			Name        string         `bun:"name"`
			Purl        sql.NullString `bun:"purl"`
		}
		if err := f.db.DB.NewSelect().
			TableExpr(`"graph_node" AS "f"`).
			Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
			ColumnExpr(`"f"."component_id", "c"."name"`).
			ColumnExpr(finding.StatedPurl(`"f"."component_id"`)+` AS "purl"`).
			Where(`"f"."build_id" = ?`, f.build).
			Scan(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		components := make([]int64, 0, len(rows))
		for _, row := range rows {
			components = append(components, row.ComponentID)
		}
		stated, err := finding.StatedPurls(ctx, f.db.DB, f.build, components)
		if err != nil {
			t.Fatal(err)
		}

		seen := map[string]sql.NullString{}
		for _, row := range rows {
			if got := stated[row.ComponentID]; got != row.Purl {
				t.Errorf("%s is stated as %v per row and %v as sets", row.Name, row.Purl, got)
			}
			seen[row.Name] = row.Purl
		}
		if want := "pkg:oci/docker-swss@master.2-bbb?arch=amd64"; seen["docker-swss"].String != want {
			t.Errorf("the rebuilt image is stated as %v, want its open version's %s", seen["docker-swss"], want)
		}
		if want := libnl.Purl; seen[libnl.Name].String != want {
			t.Errorf("libnl is stated as %v, want its node's %s", seen[libnl.Name], want)
		}
		if got, held := seen[teamd.Name]; !held || got.Valid {
			t.Errorf("teamd, no longer shipped, is stated as %v (held %t), want nothing", got, held)
		}
	})
}
