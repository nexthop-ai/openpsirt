// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What matching a typed name against the names builds stated adds to the
// findings list, on a product of several full-size builds and a year of
// weekly rescans on one of them.
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

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// statedBuilds is how many builds of the product hold the full image.
const statedBuilds = 8

func TestMeasureSearchingByTheNameABuildStated(t *testing.T) {
	doc := fullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		store := finding.NewStore(db.DB)
		now := time.Now().UTC()
		first := doc.Snapshot(graph.Described{Name: "sonic", Version: "1.0"})
		var seq int
		scanned := func(buildID int64, snap graph.Snapshot, when time.Time) {
			seq++
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				BuildID: buildID, ContentHash: fmt.Sprintf("scan-%d", seq), BuiltAt: when,
				ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := world.ApplyGraph(ctx, db.DB, buildID, scan.ID, snap); err != nil {
				t.Fatal(err)
			}
		}

		// Every package moves two hundredths at a time, weekly, for a year,
		// on the build the findings are read from: the closed nodes a search
		// reads as well as the open ones.
		current := append([]graph.Described(nil), first.Components...)
		at := map[string]int{}
		for i, c := range current {
			at[c.Purl] = i
		}
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
		const weeks = 52
		scanned(w.Build.ID, snapshot(), now.Add(-(weeks+1)*7*24*time.Hour))
		for step := 1; step <= weeks; step++ {
			for i, c := range current {
				if c.Purl == "" || i%100 != (2*step)%100 && i%100 != (2*step+1)%100 {
					continue
				}
				bumped := c
				bumped.Version = fmt.Sprintf("%s+moved%d", c.Version, step)
				bumped.Purl = strings.Replace(c.Purl, "@"+c.Version, "@"+bumped.Version, 1)
				current[i] = bumped
			}
			scanned(w.Build.ID, snapshot(), now.Add(-time.Duration(weeks+1-step)*7*24*time.Hour))
		}
		// The other builds of the product hold the image as first stated.
		for n := range statedBuilds - 1 {
			tag := w.DeclareBranchOrTag(w.Product, fmt.Sprintf("v1.%d", n), catalog.Tag, nil)
			scanned(w.BuildFor(tag, w.Customer).ID, first, now.Add(-time.Hour))
		}

		// One issue on every package of the read build.
		run, err := store.Begin(ctx, finding.Run{BuildID: w.Build.ID, Scanner: "measure",
			ScannerVersion: "0", DatabaseVersion: "0", RanHere: true})
		if err != nil {
			t.Fatal(err)
		}
		var reported []finding.Reported
		for i, c := range current {
			if c.Purl != "" {
				reported = append(reported, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
					Component: c,
				})
			}
		}
		if _, err := store.Apply(ctx, w.Build.ID, run.ID, reported); err != nil {
			t.Fatal(err)
		}
		dbtest.SettleStatistics(t, db)

		var nodes int
		if err := db.DB.NewSelect().TableExpr(`"graph_node"`).ColumnExpr(`COUNT(*)`).Scan(ctx, &nodes); err != nil {
			t.Fatal(err)
		}
		t.Logf("%d builds, %d nodes, %d findings", statedBuilds, nodes, len(reported))

		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead}}, 0)
		scope := finding.Scope{ProductID: &w.Product.ID}
		median := func(read func() error) time.Duration {
			var took []time.Duration
			for range 6 {
				start := time.Now()
				if err := read(); err != nil {
					t.Fatal(err)
				}
				took = append(took, time.Since(start))
			}
			took = took[1:]
			slices.Sort(took)
			return took[len(took)/2]
		}
		for _, term := range []string{"ssl", "lib", "linux-image"} {
			like := "%" + term + "%"
			var matched []int64
			stated := median(func() (err error) {
				matched, err = finding.StatedAs(ctx, db.DB, []int64{w.Product.ID}, false,
					`"n"."name_folded" LIKE ?`+database.LikeClause, like)
				return err
			})
			listed := median(func() error {
				_, _, err := store.Groups(ctx, who, scope, 50, 0, finding.Filter{Search: term})
				return err
			})
			t.Logf("search %q: %d components stated under it, read in %v; the list's first page in %v",
				term, len(matched), stated, listed)
		}
		exact := median(func() error {
			_, err := finding.StatedAs(ctx, db.DB, []int64{w.Product.ID}, false,
				`"n"."name_folded" IN (?)`, bun.List([]string{graph.Folded("openssl")}))
			return err
		})
		listed := median(func() error {
			_, _, err := store.Groups(ctx, who, scope, 50, 0, finding.Filter{Components: []string{"openssl"}})
			return err
		})
		t.Logf("component openssl: stated components read in %v; the list's first page in %v", exact, listed)
	})
}
