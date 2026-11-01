// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the reads beneath a component cost on a real image rescans have moved
// versions in: one rescan, and a year of weekly ones.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package finding_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// One rescan ten days after the first scan moves the kernel and every
// hundredth package to a new version.
func TestMeasureTheTrendBeneathAComponentARescanMoved(t *testing.T) {
	measureBeneathMoved(t, 1)
}

// Fifty-two weekly rescans, each moving two hundredths of the packages, and
// every fourth the kernel.
func TestMeasureTheTrendBeneathAComponentOverAYearOfRescans(t *testing.T) {
	measureBeneathMoved(t, 52)
}

func measureBeneathMoved(t *testing.T, rescans int) {
	doc := fullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		store := finding.NewStore(db.DB)
		now := time.Now().UTC()
		first := doc.Snapshot(graph.Described{Name: "sonic", Version: "1.0"})

		// Each package of the first scan by its position, and where it stands
		// now.
		at := map[string]int{}
		kernel := -1
		var packageAt []int
		pulls := map[string]int{}
		for _, d := range first.Dependencies {
			pulls[d.Parent.Purl]++
		}
		for i, c := range first.Components {
			if c.Purl == "" {
				continue
			}
			at[c.Purl] = i
			packageAt = append(packageAt, i)
			if kernel < 0 && strings.Contains(c.Purl, "/linux-image-") {
				kernel = i
			}
		}
		if kernel < 0 {
			t.Fatal("the image carries no kernel")
		}
		current := append([]graph.Described(nil), first.Components...)
		fixed := map[int]bool{}
		kernelFixed := map[int]bool{}
		snapshot := func() graph.Snapshot {
			present := func(c graph.Described) graph.Described {
				if i, ok := at[c.Purl]; ok && c.Purl != "" {
					return current[i]
				}
				return c
			}
			snap := graph.Snapshot{Root: first.Root, Components: append([]graph.Described(nil), current...)}
			for _, d := range first.Dependencies {
				snap.Dependencies = append(snap.Dependencies,
					graph.Dependency{Parent: present(d.Parent), Child: present(d.Child), Kind: d.Kind})
			}
			return snap
		}
		move := func(i int, step int) {
			c := current[i]
			bumped := c
			bumped.Version = fmt.Sprintf("%s+moved%d", c.Version, step)
			bumped.Purl = strings.Replace(c.Purl, "@"+c.Version, "@"+bumped.Version, 1)
			if bumped.UpstreamVersion != "" {
				bumped.UpstreamVersion = fmt.Sprintf("%s+moved%d", c.UpstreamVersion, step)
			}
			current[i] = bumped
		}

		// Every package carries one issue and the kernel a real one's. A move
		// fixes the issue on every second package it moves, and half of what
		// is left on the kernel.
		report := func() []finding.Reported {
			var out []finding.Reported
			for _, i := range packageAt {
				if !fixed[i] {
					out = append(out, finding.Reported{
						Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
						Component: current[i],
					})
				}
			}
			for k := range kernelIssues - 1 {
				if !kernelFixed[k] {
					out = append(out, finding.Reported{
						Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2025-%05d", k), Severity: "medium"},
						Component: current[kernel],
					})
				}
			}
			return out
		}
		scanned := func(hash string, when time.Time) {
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				BuildID: w.Build.ID, ContentHash: hash, BuiltAt: when, ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := world.ApplyGraph(ctx, db.DB, w.Build.ID, scan.ID, snapshot()); err != nil {
				t.Fatal(err)
			}
			run, err := store.Begin(ctx, finding.Run{
				BuildID: w.Build.ID, Scanner: "measure", ScannerVersion: "0",
				DatabaseVersion: "0", RanHere: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.NewUpdate().Table("scan_run").Set(`"started_at" = ?`, when).
				Where(`"id" = ?`, run.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Apply(ctx, w.Build.ID, run.ID, report()); err != nil {
				t.Fatal(err)
			}
		}

		every := 10 * 24 * time.Hour
		if rescans > 1 {
			every = 7 * 24 * time.Hour
		}
		scanned("scan-0", now.Add(-time.Duration(rescans+1)*every))
		// The package a rescan moved that pulls in least, its issue
		// carried: the small subtree a bump lands in.
		var small graph.Described
		smallPulls := 0
		for step := 1; step <= rescans; step++ {
			moving := map[int]bool{0: true}
			if rescans > 1 {
				moving = map[int]bool{(2 * step) % 100: true, (2*step + 1) % 100: true}
			}
			for n, i := range packageAt {
				if !moving[n%100] || i == kernel {
					continue
				}
				move(i, step)
				if (n/100)%2 == 1 {
					fixed[i] = true
				}
				if !fixed[i] && (small.Purl == "" || pulls[first.Components[i].Purl] <= smallPulls) {
					small, smallPulls = current[i], pulls[first.Components[i].Purl]
				}
			}
			if rescans == 1 || step%4 == 0 {
				move(kernel, step)
				odd := false
				for k := range kernelIssues - 1 {
					if kernelFixed[k] {
						continue
					}
					if odd = !odd; odd {
						kernelFixed[k] = true
					}
				}
			}
			scanned(fmt.Sprintf("scan-%d", step), now.Add(-time.Duration(rescans+1-step)*every))
		}
		if small.Purl == "" {
			t.Fatal("no package a rescan moved carries its issue")
		}
		dbtest.SettleStatistics(t, db)

		last := snapshot()
		children := map[graph.Described]int{}
		var widest graph.Described
		for _, d := range last.Dependencies {
			if d.Parent.Name == last.Root.Name {
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
		timed := func(read func() error) []time.Duration {
			var took []time.Duration
			for range reads + 1 {
				start := time.Now()
				if err := read(); err != nil {
					t.Fatal(err)
				}
				took = append(took, time.Since(start))
			}
			return took[1:]
		}

		var replaced map[int64][]int64
		replacedTook := timed(func() (err error) {
			replaced, err = graph.Replaced(ctx, db.DB, w.Build.ID)
			return err
		})
		t.Logf("%d components the rescans replaced, read in %v", len(replaced), replacedTook)
		// The form not taken: the replaced components joined to the live ones
		// by name in one statement.
		joinedTook := timed(func() error {
			var rows []struct {
				Replaced int64 `bun:"replaced"`
				Live     int64 `bun:"live"`
			}
			return db.DB.NewSelect().TableExpr(`"graph_node" AS "nr"`).
				Join(`JOIN "component" AS "cr" ON "cr"."id" = "nr"."component_id"`).
				Join(`JOIN "component" AS "cl" ON "cl"."name_folded" = "cr"."name_folded"`).
				Join(`JOIN "graph_node" AS "nl" ON "nl"."component_id" = "cl"."id"`).
				ColumnExpr(`"nr"."component_id" AS "replaced", "nl"."component_id" AS "live"`).
				Where(`"nr"."build_id" = ?`, w.Build.ID).
				Where(`"nr"."closed_scan_id" IS NOT NULL`).
				Where(`"nl"."build_id" = ?`, w.Build.ID).
				Where(`"nl"."closed_scan_id" IS NULL`).
				Where(`NOT EXISTS (SELECT 1 FROM "graph_node" AS "ln" WHERE "ln"."build_id" = ?
					AND "ln"."closed_scan_id" IS NULL AND "ln"."component_id" = "nr"."component_id")`, w.Build.ID).
				Distinct().Scan(ctx, &rows)
		})
		t.Logf("the same joined by name in one statement, read in %v", joinedTook)

		for _, at := range []struct {
			name      string
			component graph.Described
			byName    bool
		}{
			{"the kernel", current[kernel], false},
			// The same rows asked for by the kernel's name at any version,
			// which walks nothing: what reading them costs.
			{"the kernel's name", current[kernel], true},
			{fmt.Sprintf("the widest parent, %d children", children[widest]), widest, false},
			{fmt.Sprintf("a package a rescan moved, pulling in %d", smallPulls), small, false},
			{"the root", last.Root, false},
		} {
			var beneath int64
			if at.component == last.Root {
				if err := db.DB.NewSelect().TableExpr(`"graph_node" AS "n"`).ColumnExpr(`"n"."component_id"`).
					Where(`"n"."build_id" = ?`, w.Build.ID).Where(`"n"."is_root" = ?`, true).
					Where(`"n"."closed_scan_id" IS NULL`).Limit(1).Scan(ctx, &beneath); err != nil {
					t.Fatalf("find the root: %v", err)
				}
			} else {
				beneath = idOf(at.component)
			}
			within := finding.Within{Beneath: &beneath}
			if at.byName {
				within = finding.Within{Component: at.component.Name}
			}
			var points []finding.Point
			trendTook := timed(func() (err error) {
				points, err = store.Trend(ctx, who, scope, now.Add(-12*7*24*time.Hour),
					7*24*time.Hour, 12, within)
				return err
			})
			opened, resolved := 0, 0
			for _, p := range points {
				opened += p.Opened
				resolved += p.Resolved
			}
			t.Logf("trend beneath %s: open %d eleven weeks back and %d now, %d opened, %d resolved; read in %v",
				at.name, points[0].Open, points[len(points)-1].Open, opened, resolved, trendTook)
			if at.byName {
				continue
			}
			var total int
			listTook := timed(func() (err error) {
				_, total, err = store.Groups(ctx, who, scope, 50, 0, finding.Filter{Beneath: &beneath})
				return err
			})
			t.Logf("list beneath %s: %d rows, first page read in %v", at.name, total, listTook)

			// The findings beneath, counted with the replaced components
			// united with the walk and, the forms not taken, named as a
			// second start of the walk, in its last step, or as a second
			// membership test joined by OR.
			under, err := graph.ReplacedWithin(ctx, db.DB, w.Build.ID, beneath, replaced)
			if err != nil {
				t.Fatal(err)
			}
			for _, form := range []struct {
				name  string
				where string
				args  []any
			}{
				{"united with the walk", `"f"."component_id" IN (?)`,
					[]any{graph.WithinAnd(db.DB, w.Build.ID, beneath, under)}},
				{"named as a second start of the walk", `"f"."component_id" IN (?)`,
					[]any{db.NewRaw(`WITH RECURSIVE "down" AS (
		SELECT "n"."id" AS "node" FROM "graph_node" AS "n"
		WHERE "n"."build_id" = ? AND "n"."closed_scan_id" IS NULL AND "n"."component_id" = ?
		UNION
		SELECT "n"."id" FROM "graph_node" AS "n" WHERE "n"."build_id" = ? AND "n"."component_id" IN (?)
		UNION
		SELECT "e"."child_id" FROM "down" AS "d" CROSS JOIN "graph_edge" AS "e"
		WHERE "e"."build_id" = ? AND "e"."closed_scan_id" IS NULL AND "e"."parent_id" = "d"."node"
		  AND "e"."parent_id" <> "e"."child_id"
	)
	SELECT DISTINCT "n"."component_id" FROM "down" AS "d" JOIN "graph_node" AS "n" ON "n"."id" = "d"."node"`,
						w.Build.ID, beneath, w.Build.ID, bun.List(append([]int64{0}, under...)), w.Build.ID)}},
				{"named in the walk's last step", `"f"."component_id" IN (?)`,
					[]any{db.NewRaw(`WITH RECURSIVE "down" AS (
		SELECT "n"."id" AS "node" FROM "graph_node" AS "n"
		WHERE "n"."build_id" = ? AND "n"."closed_scan_id" IS NULL AND "n"."component_id" = ?
		UNION
		SELECT "e"."child_id" FROM "down" AS "d" CROSS JOIN "graph_edge" AS "e"
		WHERE "e"."build_id" = ? AND "e"."closed_scan_id" IS NULL AND "e"."parent_id" = "d"."node"
		  AND "e"."parent_id" <> "e"."child_id"
	)
	SELECT DISTINCT "n"."component_id" FROM "graph_node" AS "n"
	WHERE "n"."build_id" = ? AND ("n"."id" IN (SELECT "d"."node" FROM "down" AS "d")
	  OR "n"."component_id" IN (?))`,
						w.Build.ID, beneath, w.Build.ID, w.Build.ID, bun.List(append([]int64{0}, under...)))}},
				{"two joined by OR", `("f"."component_id" IN (?) OR "f"."component_id" IN (?))`,
					[]any{graph.Within(db.DB, w.Build.ID, beneath), bun.List(append([]int64{0}, under...))}},
			} {
				var count int64
				formTook := timed(func() (err error) {
					count, err = db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
						Where(`"f"."build_id" = ?`, w.Build.ID).Where(form.where, form.args...).Count(ctx)
					return err
				})
				t.Logf("findings beneath %s, %s: %d, counted in %v", at.name, form.name, count, formTook)
			}
		}

		// The tree's step around the kernel, which counts beneath each
		// neighbor.
		var above, below []graph.Neighbor
		aroundTook := timed(func() (err error) {
			above, below, err = graph.NewStore(db.DB).Around(ctx, who, w.Build.ID, current[kernel].Name,
				graph.Choice{Version: current[kernel].Version})
			return err
		})
		t.Logf("around the kernel: %d above and %d below, read in %v", len(above), len(below), aroundTook)
	})
}
