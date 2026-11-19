// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the reads matching publishers' statements to components cost on a
// product holding several builds of a real image.
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
	"github.com/nexthop-ai/openpsirt/internal/sbom/sbomtest"
)

// statementBuilds is how many variants of one branch the product holds, each
// a build of the full-size image, and statementsSaid how many statements a
// publisher makes about its components, each placed inside a product of its
// own: half a product this product ships, half one it does not. An upstream
// makes as many statements awaiting review, one in offeredShare about a
// component shipped here and the rest about components nothing ships, as a
// real upstream's document is.
const (
	statementBuilds = 6
	statementsSaid  = 3585
	offeredShare    = 6
)

func TestMeasureReadsMatchingStatementsToComponents(t *testing.T) {
	doc := sbomtest.FullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		store := finding.NewStore(db.DB)
		snap := doc.Snapshot(graph.Described{Name: "sonic", Version: "1.0"})

		var packages []graph.Described
		for _, c := range snap.Components {
			if c.Purl != "" && c.Name != "" && c.Version != "" {
				packages = append(packages, c)
			}
		}
		if len(packages) < statementsSaid {
			t.Fatalf("the image holds %d packages, fewer than the %d statements", len(packages), statementsSaid)
		}
		reported := make([]finding.Reported, 0, len(packages))
		for i, c := range packages {
			reported = append(reported, finding.Reported{
				Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
				Component: c,
			})
		}

		builds := []int64{w.Build.ID}
		for b := 1; b < statementBuilds; b++ {
			variant := w.DeclareVariant(w.Product, fmt.Sprintf("variant-%02d", b), true)
			builds = append(builds, w.BuildFor(w.Branch, variant).ID)
		}
		seeded := time.Now()
		for _, build := range builds {
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				BuildID: build, ContentHash: fmt.Sprintf("build-%d", build), BuiltAt: time.Now().UTC(),
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
			if _, err := store.Apply(ctx, build, run.ID, reported); err != nil {
				t.Fatal(err)
			}
		}

		who := access.NewPerson(w.Person.ID, "a reader", false,
			map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead,
				access.PublicTriage, access.PrivateTriage}}, 0)
		said := make([]finding.Statement, 0, statementsSaid)
		offered := make([]finding.Statement, 0, statementsSaid)
		for i, c := range packages[:statementsSaid] {
			within := fmt.Sprintf("acme-platform-%d", i)
			if i%2 == 0 {
				within = packages[(i*7+1)%len(packages)].Name
			}
			issue := fmt.Sprintf("CVE-2026-%05d", i)
			said = append(said, finding.Statement{
				Vulnerability: issue, Component: c.Name, Purl: c.Purl, About: c.Version,
				Within: within, WithinAbout: "1.0", Placement: finding.PlacedInside,
				Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
			})
			component := fmt.Sprintf("absent-%d", i)
			if i%offeredShare == 0 {
				component = c.Name
			}
			offered = append(offered, finding.Statement{
				Vulnerability: issue, Component: component, About: c.Version,
				Status: "not_affected", Justification: "vulnerable_code_not_present",
			})
		}
		if _, _, err := store.RecordStatements(ctx, who, w.Product.ID, finding.Supplied{
			Source: finding.FromVex, Publisher: "Measure", Document: "measure.json", Digest: "sha256:measure",
		}, said); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.RecordStatements(ctx, who, w.Product.ID, finding.Supplied{
			Source: finding.FromVex, Publisher: "Upstream", Document: "upstream.json", Digest: "sha256:upstream",
		}, offered); err != nil {
			t.Fatal(err)
		}
		// Offered for review: an upstream's statements nothing placed.
		if _, err := db.DB.NewUpdate().TableExpr(`"received_vex_statement"`).
			Set(`"source" = ?`, finding.FromUpstream).Set(`"placement" = NULL`).
			Where(`"publisher" = ?`, "upstream").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		dbtest.SettleStatistics(t, db)
		var findings int
		if err := db.DB.NewSelect().TableExpr(`"finding"`).ColumnExpr(`COUNT(*)`).Scan(ctx, &findings); err != nil {
			t.Fatal(err)
		}
		t.Logf("%d builds of %d packages, %d findings, %d statements placed and %d offered; seeded in %v",
			len(builds), len(packages), findings, len(said), len(offered), time.Since(seeded).Round(time.Second))

		median := func(name string, read func() (int, error)) {
			t.Helper()
			const reads = 5
			var took []time.Duration
			held := 0
			for range reads + 1 {
				start := time.Now()
				n, err := read()
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				took = append(took, time.Since(start))
				held = n
			}
			took = took[1:]
			slices.Sort(took)
			t.Logf("%s: %d rows, median of %d reads %v", name, held, reads, took[reads/2].Round(time.Millisecond))
		}
		everywhere := finding.Scope{ProductID: &w.Product.ID}
		for _, f := range []struct {
			name   string
			filter finding.Filter
		}{
			{"narrowed by publisher", finding.Filter{Publishers: []string{"Measure"}}},
			{"narrowed by what was said", finding.Filter{VexStatus: []string{"not_affected"}}},
		} {
			median("findings "+f.name, func() (int, error) {
				groups, _, err := store.Groups(ctx, who, everywhere, 50, 0, f.filter)
				return len(groups), err
			})
		}
		median("offers for review", func() (int, error) {
			offers, err := store.Offers(ctx, who, w.Product.ID)
			return len(offers), err
		})
	})
}
