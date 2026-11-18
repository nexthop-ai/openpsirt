// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What a build trend costs over a build of a real image uploaded nightly.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package ingest_test

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
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom/sbomtest"
)

// trendNights is how many nightly uploads the build receives, the most a build
// trend plots, each scanned once. Each drops one leaf package in thirty and
// restores the night before's, so every upload closes and reopens some issues.
// Every package carries one issue, and the kernel trendKernelIssues.
const (
	trendNights       = 50
	trendDropShare    = 30
	trendKernelIssues = 3000
)

func TestMeasureABuildTrendOverNightlyUploads(t *testing.T) {
	doc := sbomtest.FullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		store := finding.NewStore(db.DB)
		uploads := ingest.NewStore(db.DB)
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
		if kernel < 0 {
			t.Fatal("the image carries no kernel, so this is not the image it models")
		}
		dropped := func(night, i int) bool {
			n, ok := leaf[i]
			return ok && night > 0 && n%trendDropShare == night%trendDropShare
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
			for n := range trendKernelIssues {
				out = append(out, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2025-%05d", n), Severity: "critical"},
					Component: first.Components[kernel],
				})
			}
			return out
		}

		seeded := time.Now()
		for night := range trendNights {
			when := now.Add(-time.Duration(trendNights-night)*24*time.Hour - 12*time.Hour)
			scan, _, err := uploads.Record(ctx, ingest.Arriving{
				BuildID: w.Build.ID, ContentHash: fmt.Sprintf("night-%d", night), BuiltAt: when,
				ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.NewUpdate().Table("scan").Set(`"received_at" = ?`, when.Add(time.Minute)).
				Where(`"id" = ?`, scan.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			snap := snapshot(night)
			if _, err := world.ApplyGraph(ctx, db.DB, w.Build.ID, scan.ID, snap); err != nil {
				t.Fatal(err)
			}
			if err := uploads.Made(ctx, scan.ID, len(snap.Components), len(snap.Components), ""); err != nil {
				t.Fatal(err)
			}
			run, err := store.Begin(ctx, finding.Run{
				BuildID: w.Build.ID, Scanner: "measure", ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.NewUpdate().Table("scan_run").Set(`"started_at" = ?`, when.Add(time.Hour)).
				Where(`"id" = ?`, run.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Apply(ctx, w.Build.ID, run.ID, report(night)); err != nil {
				t.Fatal(err)
			}
			if err := store.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
				t.Fatal(err)
			}
		}
		dbtest.SettleStatistics(t, db)
		var findings int
		if err := db.DB.NewSelect().TableExpr(`"finding"`).ColumnExpr(`COUNT(*)`).Scan(ctx, &findings); err != nil {
			t.Fatal(err)
		}
		t.Logf("one build of %d packages, %d nightly uploads: %d findings; seeded in %v",
			len(packageAt), trendNights, findings, time.Since(seeded).Round(time.Second))

		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead}}, 0)
		scope := finding.Scope{ProductID: &w.Product.ID, BranchOrTagID: &w.Branch.ID, VariantID: &w.Customer.ID}
		for _, limit := range []int{2, 12, trendNights} {
			const reads = 5
			var took []time.Duration
			var points []ingest.UploadPoint
			for range reads + 1 {
				start := time.Now()
				var err error
				if points, err = uploads.BuildTrend(ctx, who, scope, finding.Within{}, limit); err != nil {
					t.Fatal(err)
				}
				took = append(took, time.Since(start))
			}
			took = took[1:]
			slices.Sort(took)
			t.Logf("build trend of %d uploads: %d points, median of %d reads %v", limit, len(points), reads,
				took[reads/2].Round(time.Millisecond))
		}
	})
}
