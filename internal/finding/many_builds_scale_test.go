// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the reads across a product cost when it holds many builds of one image.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package finding_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom/sbomtest"
)

// manyBuilds is how many variants of one branch the product holds, and
// manyNights how many uploads each receives after its first, each dropping
// one leaf package in thirty and restoring the night before's. Every package
// carries one issue, and the kernel manyKernelIssues: a real image's kernel
// holds most of its findings, one per issue at each of its placements.
const (
	manyBuilds       = 15
	manyNights       = 2
	manyKernelIssues = 3000
)

func TestMeasureReadsAcrossManyBuilds(t *testing.T) {
	doc := sbomtest.FullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		store := finding.NewStore(db.DB)
		now := time.Now().UTC()
		first := doc.Snapshot(graph.Described{Name: "sonic", Version: "1.0"})

		pulls := map[string]int{}
		for _, d := range first.Dependencies {
			pulls[d.Parent.Purl]++
		}
		var packageAt []int
		leaf := map[int]int{}
		kernel := -1
		for i, c := range first.Components {
			if c.Purl == "" {
				continue
			}
			if kernel < 0 && strings.Contains(c.Purl, "/linux-image-") {
				kernel = i
			}
			packageAt = append(packageAt, i)
			if pulls[c.Purl] == 0 {
				leaf[i] = len(leaf)
			}
		}
		dropped := func(night, i int) bool {
			n, ok := leaf[i]
			return ok && night > 0 && n%removedShare == night%removedShare
		}
		snapshot := func(night int) graph.Snapshot {
			snap := graph.Snapshot{Root: first.Root}
			gone := map[graph.Described]bool{}
			for i, c := range first.Components {
				if dropped(night, i) {
					gone[c] = true
					continue
				}
				snap.Components = append(snap.Components, c)
			}
			for _, d := range first.Dependencies {
				if !gone[d.Child] && !gone[d.Parent] {
					snap.Dependencies = append(snap.Dependencies, d)
				}
			}
			return snap
		}
		report := func(night int) []finding.Reported {
			var out []finding.Reported
			for _, i := range packageAt {
				if !dropped(night, i) {
					out = append(out, finding.Reported{
						Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
						Component: first.Components[i],
					})
				}
			}
			for n := range manyKernelIssues {
				out = append(out, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2025-%05d", n), Severity: "high"},
					Component: first.Components[kernel],
				})
			}
			return out
		}
		if kernel < 0 {
			t.Fatal("the image carries no kernel, so this is not the image it models")
		}

		builds := []int64{w.Build.ID}
		for b := 1; b < manyBuilds; b++ {
			variant := w.DeclareVariant(w.Product, fmt.Sprintf("variant-%02d", b), true)
			builds = append(builds, w.BuildFor(w.Branch, variant).ID)
		}
		seeded := time.Now()
		for _, build := range builds {
			for night := 0; night <= manyNights; night++ {
				when := now.Add(-time.Duration(manyNights-night)*24*time.Hour - 12*time.Hour)
				scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
					BuildID: build, ContentHash: fmt.Sprintf("build-%d-night-%d", build, night), BuiltAt: when,
					ParserVersion: "measure",
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.DB.NewUpdate().Table("scan").Set(`"received_at" = ?`, when.Add(-time.Minute)).
					Where(`"id" = ?`, scan.ID).Exec(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := world.ApplyGraph(ctx, db.DB, build, scan.ID, snapshot(night)); err != nil {
					t.Fatal(err)
				}
				run, err := store.Begin(ctx, finding.Run{
					BuildID: build, Scanner: "measure", ScannerVersion: "0",
					DatabaseVersion: "0", RanHere: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.DB.NewUpdate().Table("scan_run").Set(`"started_at" = ?`, when).
					Where(`"id" = ?`, run.ID).Exec(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Apply(ctx, build, run.ID, report(night)); err != nil {
					t.Fatal(err)
				}
			}
		}
		dbtest.SettleStatistics(t, db)
		var findings, open int
		if err := db.DB.NewSelect().TableExpr(`"finding"`).ColumnExpr(`COUNT(*)`).Scan(ctx, &findings); err != nil {
			t.Fatal(err)
		}
		if err := db.DB.NewSelect().TableExpr(`"finding"`).ColumnExpr(`COUNT(*)`).
			Where(`"closed_at" IS NULL`).Scan(ctx, &open); err != nil {
			t.Fatal(err)
		}
		t.Logf("%d builds of %d packages, %d nights each after the first: %d findings, %d open; seeded in %v",
			len(builds), len(packageAt), manyNights, findings, open, time.Since(seeded).Round(time.Second))

		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead}}, 0)
		everywhere := finding.Scope{ProductID: &w.Product.ID}
		one := finding.Scope{ProductID: &w.Product.ID, BranchOrTagID: &w.Branch.ID, VariantID: &w.Customer.ID}
		median := func(name string, read func() error) {
			t.Helper()
			const reads = 5
			var took []time.Duration
			for range reads + 1 {
				start := time.Now()
				if err := read(); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				took = append(took, time.Since(start))
			}
			took = took[1:]
			slices.Sort(took)
			t.Logf("%s: median of %d reads %v", name, reads, took[reads/2].Round(time.Millisecond))
		}
		for _, s := range []struct {
			name  string
			scope finding.Scope
		}{{"every build", everywhere}, {"one build", one}} {
			median("trend over 30 days, "+s.name, func() error {
				_, err := store.Trend(ctx, who, s.scope, now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
				return err
			})
			median("burndown, "+s.name, func() error {
				_, err := store.Burndown(ctx, who, s.scope, time.Time{}, "", finding.Within{})
				return err
			})
			median("unassigned, "+s.name, func() error {
				_, _, err := store.Unassigned(ctx, who, s.scope, kind.Dependency, 25, 0)
				return err
			})
			median("remediation, "+s.name, func() error {
				_, err := store.Remediation(ctx, who, s.scope, now.Add(-90*24*time.Hour), now)
				return err
			})
		}
	})
}
