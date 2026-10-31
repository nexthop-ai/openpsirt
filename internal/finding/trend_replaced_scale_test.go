// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the trend beneath a component costs on a real image a rescan has moved
// versions in.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package finding_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

func TestMeasureTheTrendBeneathAComponentARescanMoved(t *testing.T) {
	doc := fullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		store := finding.NewStore(db.DB)
		now := time.Now().UTC()
		first := doc.Snapshot(graph.Described{Name: "sonic", Version: "1.0"})

		// The kernel and every hundredth other package move to a new version.
		moved := map[string]graph.Described{}
		var kernel graph.Described
		packages := 0
		for _, c := range first.Components {
			if c.Purl == "" {
				continue
			}
			packages++
			isKernel := strings.Contains(c.Purl, "/linux-image-") && kernel.Purl == ""
			if !isKernel && packages%100 != 0 {
				continue
			}
			bumped := c
			bumped.Version = c.Version + "+moved"
			bumped.Purl = strings.Replace(c.Purl, "@"+c.Version, "@"+bumped.Version, 1)
			if bumped.UpstreamVersion != "" {
				bumped.UpstreamVersion += "+moved"
			}
			moved[c.Purl] = bumped
			if isKernel {
				kernel = c
			}
		}
		if kernel.Purl == "" {
			t.Fatal("the image carries no kernel")
		}
		bump := func(c graph.Described) graph.Described {
			if b, ok := moved[c.Purl]; ok && c.Purl != "" {
				return b
			}
			return c
		}
		second := graph.Snapshot{Root: first.Root}
		for _, c := range first.Components {
			second.Components = append(second.Components, bump(c))
		}
		for _, d := range first.Dependencies {
			second.Dependencies = append(second.Dependencies,
				graph.Dependency{Parent: bump(d.Parent), Child: bump(d.Child), Kind: d.Kind})
		}

		// Every package carries one issue and the kernel a real one's. The
		// rescan fixes half of what sits on a moved package and carries the
		// rest.
		report := func(snap graph.Snapshot, rescan bool) []finding.Reported {
			var out []finding.Reported
			for i, c := range snap.Components {
				if c.Purl == "" {
					continue
				}
				_, wasMoved := moved[first.Components[i].Purl]
				if !rescan || !wasMoved || i%2 == 0 {
					out = append(out, finding.Reported{
						Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
						Component: c,
					})
				}
				if strings.Contains(c.Purl, "/linux-image-") && first.Components[i].Purl == kernel.Purl {
					for k := range kernelIssues - 1 {
						if rescan && k%2 == 0 {
							continue
						}
						out = append(out, finding.Reported{
							Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2025-%05d", k), Severity: "medium"},
							Component: c,
						})
					}
				}
			}
			return out
		}
		scanned := func(snap graph.Snapshot, hash string, at time.Time, rescan bool) {
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				BuildID: w.Build.ID, ContentHash: hash, BuiltAt: at, ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := world.ApplyGraph(ctx, db.DB, w.Build.ID, scan.ID, snap); err != nil {
				t.Fatal(err)
			}
			run, err := store.Begin(ctx, finding.Run{
				BuildID: w.Build.ID, Scanner: "measure", ScannerVersion: "0",
				DatabaseVersion: "0", RanHere: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.NewUpdate().Table("scan_run").Set(`"started_at" = ?`, at).
				Where(`"id" = ?`, run.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Apply(ctx, w.Build.ID, run.ID, report(snap, rescan)); err != nil {
				t.Fatal(err)
			}
		}
		scanned(first, "first", now.Add(-20*24*time.Hour), false)
		scanned(second, "second", now.Add(-10*24*time.Hour), true)
		dbtest.SettleStatistics(t, db)

		// The component with the most children, the root apart.
		children := map[graph.Described]int{}
		var widest graph.Described
		for _, d := range second.Dependencies {
			if d.Parent.Name == second.Root.Name {
				continue
			}
			children[d.Parent]++
			if children[d.Parent] > children[widest] {
				widest = d.Parent
			}
		}
		idOf := func(c graph.Described) int64 {
			var id int64
			if err := db.DB.NewSelect().TableExpr(`"component" AS "c"`).
				Join(`JOIN "graph_node" AS "n" ON "n"."component_id" = "c"."id"`).
				ColumnExpr(`"c"."id"`).Where(`"c"."name" = ?`, c.Name).Where(`"c"."version" = ?`, c.Version).
				Where(`"n"."build_id" = ?`, w.Build.ID).Where(`"n"."closed_scan_id" IS NULL`).
				Limit(1).Scan(ctx, &id); err != nil {
				t.Fatalf("find %s %s: %v", c.Name, c.Version, err)
			}
			return id
		}

		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead}}, 0)
		scope := finding.Scope{ProductID: &w.Product.ID}
		const reads = 5
		var replacedTook []time.Duration
		var replaced map[int64][]int64
		for range reads + 1 {
			start := time.Now()
			var err error
			if replaced, err = graph.Replaced(ctx, db.DB, w.Build.ID); err != nil {
				t.Fatal(err)
			}
			replacedTook = append(replacedTook, time.Since(start))
		}
		t.Logf("%d components the rescan replaced, read in %v", len(replaced), replacedTook[1:])
		for _, at := range []struct {
			name      string
			component graph.Described
			byName    bool
		}{
			{"the kernel", moved[kernel.Purl], false},
			// The same rows asked for by the kernel's name at any version,
			// which walks nothing: what reading them costs.
			{"the kernel's name", moved[kernel.Purl], true},
			{fmt.Sprintf("the widest parent, %d children", children[widest]), widest, false},
		} {
			beneath := idOf(at.component)
			within := finding.Within{Beneath: &beneath}
			if at.byName {
				within = finding.Within{Component: at.component.Name}
			}
			var took []time.Duration
			var points []finding.Point
			for range reads + 1 {
				start := time.Now()
				var err error
				points, err = store.Trend(ctx, who, scope, now.Add(-12*7*24*time.Hour),
					7*24*time.Hour, 12, within)
				if err != nil {
					t.Fatal(err)
				}
				took = append(took, time.Since(start))
			}
			opened, resolved := 0, 0
			for _, p := range points {
				opened += p.Opened
				resolved += p.Resolved
			}
			t.Logf("%s: open %d two weeks back and %d now, %d opened, %d resolved; read in %v",
				at.name, points[9].Open, points[len(points)-1].Open, opened, resolved, took[1:])
		}

		// The list beneath the widest parent, its first page, and the tree's
		// step around the kernel, which counts beneath each neighbor.
		beneath := idOf(widest)
		var listed []time.Duration
		var total int
		for range reads + 1 {
			start := time.Now()
			var err error
			if _, total, err = store.Groups(ctx, who, scope, 50, 0, finding.Filter{Beneath: &beneath}); err != nil {
				t.Fatal(err)
			}
			listed = append(listed, time.Since(start))
		}
		t.Logf("the list beneath the widest parent: %d rows, first page read in %v", total, listed[1:])
		var around []time.Duration
		var above, below []graph.Neighbor
		for range reads + 1 {
			start := time.Now()
			var err error
			if above, below, err = graph.NewStore(db.DB).Around(ctx, who, w.Build.ID, moved[kernel.Purl].Name,
				graph.Choice{Version: moved[kernel.Purl].Version}); err != nil {
				t.Fatal(err)
			}
			around = append(around, time.Since(start))
		}
		t.Logf("around the kernel: %d above and %d below, read in %v", len(above), len(below), around[1:])
	})
}
