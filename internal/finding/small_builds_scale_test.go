// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the reads across a product cost when it holds many small builds.
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
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// smallPackages is how many packages each small build ships, each carrying
// one issue.
const smallPackages = 24

func TestMeasureReadsAcrossManySmallBuilds(t *testing.T) {
	for _, builds := range []int{200, 1000} {
		t.Run(fmt.Sprintf("%d builds", builds), func(t *testing.T) {
			dbtest.Each(t, func(t *testing.T, db *database.DB) {
				measureSmallBuilds(t, db, builds)
			})
		})
	}
}

func measureSmallBuilds(t *testing.T, db *database.DB, builds int) {
	ctx := t.Context()
	w := world.New(t, db)
	store := finding.NewStore(db.DB)
	now := time.Now().UTC()

	root := graph.Described{Name: "small", Version: "1.0"}
	snap := graph.Snapshot{Root: root}
	var report []finding.Reported
	for i := range smallPackages {
		c := graph.Described{
			Name: fmt.Sprintf("pkg-%02d", i), Version: "1.0",
			Purl: fmt.Sprintf("pkg:deb/debian/pkg-%02d@1.0", i),
		}
		snap.Components = append(snap.Components, c)
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: root, Child: c})
		report = append(report, finding.Reported{
			Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
			Component: c,
		})
	}

	ids := []int64{w.Build.ID}
	for b := 1; b < builds; b++ {
		variant := w.DeclareVariant(w.Product, fmt.Sprintf("variant-%04d", b), true)
		ids = append(ids, w.BuildFor(w.Branch, variant).ID)
	}
	seeded := time.Now()
	for _, build := range ids {
		when := now.Add(-24 * time.Hour)
		scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
			BuildID: build, ContentHash: fmt.Sprintf("build-%d", build), BuiltAt: when,
			ParserVersion: "measure",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := world.ApplyGraph(ctx, db.DB, build, scan.ID, snap); err != nil {
			t.Fatal(err)
		}
		run, err := store.Begin(ctx, finding.Run{
			BuildID: build, Scanner: "measure", ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Apply(ctx, build, run.ID, report); err != nil {
			t.Fatal(err)
		}
	}
	dbtest.SettleStatistics(t, db)
	t.Logf("%d builds of %d packages: seeded in %v", len(ids), smallPackages, time.Since(seeded).Round(time.Second))

	who := access.NewPerson(1, "a reader", false,
		map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead}}, 0)
	everywhere := finding.Scope{ProductID: &w.Product.ID}
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
	median("trend over 30 days", func() error {
		_, err := store.Trend(ctx, who, everywhere, now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		return err
	})
	median("burndown", func() error {
		_, err := store.Burndown(ctx, who, everywhere, time.Time{}, "", finding.Within{})
		return err
	})
	median("unassigned", func() error {
		_, _, err := store.Unassigned(ctx, who, everywhere, kind.Dependency, 25, 0)
		return err
	})
	median("assigned to somebody", func() error {
		_, _, err := store.AssignedTo(ctx, kind.Assignment, "", who, []int64{1}, everywhere, 25, 0)
		return err
	})
	median("overview", func() error {
		_, _, err := store.HowItStands(ctx, who, w.Product.ID)
		return err
	})
	median("remediation", func() error {
		_, err := store.Remediation(ctx, who, everywhere, now.Add(-90*24*time.Hour), now)
		return err
	})
}
