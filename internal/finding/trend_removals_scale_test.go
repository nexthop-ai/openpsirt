// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the trend costs on a real image whose nightly uploads drop packages.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package finding_test

import (
	"fmt"
	"slices"
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

// removedShare is the one in so many leaf packages a night drops; what a
// night drops comes back the night after, so every night removes and returns.
const removedShare = 30

// Sixty, 180 and 365 nightly uploads after the first scan: whether the cost
// follows the build's age.
func TestMeasureTheTrendOverNightlyRemovals(t *testing.T) {
	measureNightlyRemovals(t, 60)
}

func TestMeasureTheTrendOverHalfAYearOfNightlyRemovals(t *testing.T) {
	measureNightlyRemovals(t, 180)
}

func TestMeasureTheTrendOverAYearOfNightlyRemovals(t *testing.T) {
	measureNightlyRemovals(t, 365)
}

func measureNightlyRemovals(t *testing.T, removalNights int) {
	doc := fullSizeImage(t)
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
		// Each package by its position, and the leaves: packages pulling in
		// nothing, which a night can drop without orphaning anything.
		var packageAt []int
		leaf := map[int]int{}
		for i, c := range first.Components {
			if c.Purl == "" {
				continue
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
			var gone []graph.Described
			for i, c := range first.Components {
				if dropped(night, i) {
					gone = append(gone, c)
					continue
				}
				snap.Components = append(snap.Components, c)
			}
			for _, d := range first.Dependencies {
				if !slices.Contains(gone, d.Child) && !slices.Contains(gone, d.Parent) {
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
			return out
		}
		for night := 0; night <= removalNights; night++ {
			when := now.Add(-time.Duration(removalNights-night)*24*time.Hour - 12*time.Hour)
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				BuildID: w.Build.ID, ContentHash: fmt.Sprintf("night-%d", night), BuiltAt: when,
				ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			// The upload arrives before the run that reads it.
			if _, err := db.DB.NewUpdate().Table("scan").Set(`"received_at" = ?`, when.Add(-time.Minute)).
				Where(`"id" = ?`, scan.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := world.ApplyGraph(ctx, db.DB, w.Build.ID, scan.ID, snapshot(night)); err != nil {
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
			if _, err := store.Apply(ctx, w.Build.ID, run.ID, report(night)); err != nil {
				t.Fatal(err)
			}
		}
		dbtest.SettleStatistics(t, db)
		t.Logf("%d packages, %d leaves, one in %d dropped and back each night for %d nights",
			len(packageAt), len(leaf), removedShare, removalNights)

		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead}}, 0)
		scope := finding.Scope{ProductID: &w.Product.ID}
		const reads = 5
		for _, days := range []int{7, 30, 365} {
			var took []time.Duration
			var points []finding.Point
			for range reads + 1 {
				start := time.Now()
				var err error
				points, err = store.Trend(ctx, who, scope, now.Add(-time.Duration(days)*24*time.Hour),
					24*time.Hour, days, finding.Within{})
				if err != nil {
					t.Fatal(err)
				}
				took = append(took, time.Since(start))
			}
			took = took[1:]
			slices.Sort(took)
			var returned, restored, corrected int
			for _, p := range points {
				returned += p.Returned
				restored += p.Restored
				corrected += p.Corrected
			}
			t.Logf("trend over %d days: %d returned, %d returned after a gap, %d corrected; median of %d reads %v",
				days, returned, restored, corrected, reads, took[reads/2].Round(time.Millisecond))
		}
	})
}
