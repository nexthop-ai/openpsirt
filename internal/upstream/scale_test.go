// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What reading a real image's published documents costs a fork: the first
// read, a read over nothing that moved, and a run applying what was read.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package upstream_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// fullSizeImage reads the full-size fixture the inventory reader is tested
// against.
func fullSizeImage(t *testing.T) *sbom.Document {
	t.Helper()
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz is not available, so the full-size fixture cannot be read here")
	}
	dir, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	out, err := dir.Create("image.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("xz", "--decompress", "--stdout", "../sbom/testdata/switch-image.cdx.json.xz")
	cmd.Stdout = out
	runErr := cmd.Run()
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatalf("decompress the fixture: %v", runErr)
	}
	in, err := dir.Open("image.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	doc, err := sbom.Read(in, sbom.Limits{})
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}
	return doc
}

// The switch image shipped by the upstream and by a fork, every component with
// a package identifier carrying one issue, and a tenth of the distribution
// packages' issues agreed by the upstream not to apply because the code is not
// there, published. The fork reads it and runs its build. On PostgreSQL alone.
func TestMeasureAForkReadingARealImagesDocuments(t *testing.T) {
	doc := fullSizeImage(t)
	dbtest.Only(t, database.Postgres, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := bare(t, fixture.New(t, db))
		root := graph.Described{Purl: "pkg:generic/sonic@master.1", Name: "sonic", Version: "master.1"}
		var reported []finding.Reported
		for i, component := range doc.Components {
			if component.Purl == "" {
				continue
			}
			reported = append(reported, finding.Reported{
				Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
				Component: component,
			})
		}
		shipped := func(target *catalog.Target, hash string) {
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				TargetID: target.ID, ContentHash: hash,
				BuiltAt: time.Now().UTC().Add(-time.Hour), ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.ApplyGraph(ctx, db.DB, target.ID, scan.ID, doc.Snapshot(root)); err != nil {
				t.Fatal(err)
			}
		}
		run := func(target *catalog.Target) time.Duration {
			start := time.Now()
			ran, err := w.findings.Begin(ctx, finding.Run{TargetID: target.ID, Scanner: "measure", RanHere: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.findings.Apply(ctx, target.ID, ran.ID, reported); err != nil {
				t.Fatal(err)
			}
			return time.Since(start)
		}
		shipped(w.Target, "upstream")
		run(w.Target)
		decided := 0
		seen := map[string]bool{}
		for i, one := range reported {
			if i%10 != 0 || !strings.HasPrefix(one.Component.Purl, "pkg:deb/") ||
				seen[one.Issue.Identifier+" "+one.Component.Name] {
				continue
			}
			seen[one.Issue.Identifier+" "+one.Component.Name] = true
			w.decide(w.Target, one.Issue.Identifier, one.Component.Name, triage.CodeNotPresent)
			decided++
		}
		if err := w.Catalog.SetPublishes(ctx, w.Product.ID, true); err != nil {
			t.Fatal(err)
		}
		w.write()

		shipped(w.forkBuild, "fork")
		run(w.forkBuild)
		dbtest.SettleStatistics(t, db)
		alone := run(w.forkBuild)

		w.trust()
		start := time.Now()
		first := w.read()
		firstTook := time.Since(start)
		start = time.Now()
		again := w.read()
		againTook := time.Since(start)
		applied := run(w.forkBuild)

		var closed int
		if err := db.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr("COUNT(*)").
			Where(`"f"."target_id" = ?`, w.forkBuild.ID).
			Where(`"f"."closed_because" = ?`, string(finding.Disclaimed)).
			Scan(ctx, &closed); err != nil {
			t.Fatal(err)
		}
		var portable, statements int
		if err := db.DB.NewSelect().TableExpr(`"vex_statement" AS "ss"`).ColumnExpr("COUNT(*)").
			Where(`"ss"."product_id" = ?`, w.fork.ID).Where(`"ss"."superseded_at" IS NULL`).
			Scan(ctx, &statements); err != nil {
			t.Fatal(err)
		}
		if err := db.DB.NewSelect().TableExpr(`"vex_statement" AS "ss"`).ColumnExpr("COUNT(*)").
			Where(`"ss"."product_id" = ?`, w.fork.ID).Where(`"ss"."superseded_at" IS NULL`).
			Where(`"ss"."placement" = ?`, finding.PlacedAnybody).
			Scan(ctx, &portable); err != nil {
			t.Fatal(err)
		}
		t.Logf("%d statements recorded, %d of them holding for anybody; %d refused", statements, portable, first.Refused)
		t.Logf("%d issue-at-component pairs, %d agreed by the upstream not to apply", len(reported), decided)
		t.Logf("first read: %d documents in %s; a read over nothing moved: %d documents in %s",
			first.Documents, firstTook, again.Documents, againTook)
		t.Logf("the fork's run: %s before trusting, %s applying what was read, closing %d",
			alone, applied, closed)
	})
}
