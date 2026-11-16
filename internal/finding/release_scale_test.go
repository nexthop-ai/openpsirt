// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the release chart costs over a product's line of tagged releases of a
// real image, its kernel renamed by its own upgrades.
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
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom/sbomtest"
)

// releaseTags is the line of releases the chart is read over, and the most it
// plots by default.
const releaseTags = 24

// Every package of the full-size image under the root once, so each issue at a
// component is one finding: the rows the chart reads are the pairs it counts.
// Each tag moves a twenty-fourth of the packages to a new version, and every
// fourth tag renames the kernel by moving the version its name carries.
func TestMeasureTheReleaseChartOverAReleaseLine(t *testing.T) {
	doc := sbomtest.FullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		store := finding.NewStore(db.DB)
		first := doc.Snapshot(graph.Described{Name: "sonic", Version: "1.0"})

		var current []graph.Described
		kernel := -1
		seen := map[string]bool{}
		for _, c := range first.Components {
			if c.Purl == "" || seen[c.Purl] {
				continue
			}
			seen[c.Purl] = true
			if kernel < 0 && strings.Contains(c.Purl, "/linux-image-") {
				kernel = len(current)
			}
			current = append(current, c)
		}
		if kernel < 0 {
			t.Fatal("the image carries no kernel")
		}
		const carried = "6.12.41"
		if !strings.Contains(current[kernel].Name, carried) {
			t.Fatalf("the kernel %q does not carry %s in its name", current[kernel].Name, carried)
		}
		move := func(i, tag int) {
			c := current[i]
			bumped := c
			bumped.Version = fmt.Sprintf("%s+moved%d", c.Version, tag)
			bumped.Purl = strings.Replace(c.Purl, "@"+c.Version, "@"+bumped.Version, 1)
			current[i] = bumped
		}
		rename := func(tag int) {
			c := current[kernel]
			was := strings.SplitN(strings.TrimPrefix(c.Name, "linux-image-"), "+", 2)[0]
			now := fmt.Sprintf("6.12.%d", 41+tag)
			renamed := c
			renamed.Name = strings.Replace(c.Name, was, now, 1)
			renamed.Version = strings.Replace(c.Version, was, now, 1)
			renamed.Purl = strings.ReplaceAll(c.Purl, was, now)
			current[kernel] = renamed
		}

		releases := 0
		started := time.Now()
		for tag := range releaseTags {
			if tag > 0 {
				for i := range current {
					if i != kernel && i%releaseTags == tag {
						move(i, tag)
					}
				}
				if tag%4 == 0 {
					rename(tag)
				}
			}
			declared := w.DeclareBranchOrTag(w.Product, fmt.Sprintf("v1.%d", tag), catalog.Tag, &w.Branch.ID)
			build := w.BuildFor(declared, w.Customer)
			snap := graph.Snapshot{Root: first.Root, Components: append([]graph.Described{first.Root}, current...)}
			for _, c := range current {
				snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: first.Root, Child: c})
			}
			when := time.Now().UTC().Add(-time.Duration(releaseTags-tag) * 14 * 24 * time.Hour)
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				BuildID: build.ID, ContentHash: fmt.Sprintf("release-%d", tag), BuiltAt: when, ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := world.ApplyGraph(ctx, db.DB, build.ID, scan.ID, snap); err != nil {
				t.Fatal(err)
			}
			run, err := store.Begin(ctx, finding.Run{
				BuildID: build.ID, Scanner: "measure", ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			var reported []finding.Reported
			for i, c := range current {
				if i == kernel {
					continue
				}
				reported = append(reported, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
					Component: c,
				})
			}
			for k := range kernelIssues - 1 {
				reported = append(reported, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2025-%05d", k), Severity: "medium"},
					Component: current[kernel],
				})
			}
			applied, err := store.Apply(ctx, build.ID, run.ID, reported)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
				t.Fatal(err)
			}
			releases += applied.Opened
		}
		t.Logf("%d tags, %d open findings, seeded in %s", releaseTags, releases,
			time.Since(started).Round(time.Second))
		dbtest.SettleStatistics(t, db)

		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead}}, 0)
		scope := finding.Scope{ProductID: &w.Product.ID}
		const reads = 5
		var took []time.Duration
		var points []finding.ReleasePoint
		for n := range reads + 1 {
			start := time.Now()
			var err error
			if points, err = store.ReleaseTrend(ctx, who, scope, releaseTags); err != nil {
				t.Fatal(err)
			}
			if n > 0 {
				took = append(took, time.Since(start))
			}
		}
		plotted := 0
		for _, p := range points {
			plotted += p.Open
		}
		t.Logf("release chart: %d points, %d issues at components plotted; read in %v",
			len(points), plotted, took)
	})
}
