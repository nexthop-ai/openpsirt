// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

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

// Remediation's figures over the full-size image with fifteen issues at every
// component: ten fixed everywhere, five still open, every other issue dated.
func TestMeasureTimeToFixFromPublication(t *testing.T) {
	doc := fullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
			BuildID: w.Build.ID, ContentHash: "measure", BuiltAt: time.Now().UTC().Add(-40 * 24 * time.Hour),
			ParserVersion: "measure",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := world.ApplyGraph(ctx, db.DB, w.Build.ID, scan.ID,
			doc.Snapshot(graph.Described{Name: "sonic", Version: "1.0"})); err != nil {
			t.Fatal(err)
		}
		store := finding.NewStore(db.DB)
		opened, err := store.Begin(ctx, finding.Run{BuildID: w.Build.ID, Scanner: "measure", RanHere: true})
		if err != nil {
			t.Fatal(err)
		}
		closed, err := store.Begin(ctx, finding.Run{BuildID: w.Build.ID, Scanner: "measure", RanHere: true})
		if err != nil {
			t.Fatal(err)
		}
		var components []struct {
			ID       int64  `bun:"id"`
			Identity string `bun:"identity"`
		}
		if err := db.DB.NewSelect().TableExpr(`"component" AS "c"`).
			ColumnExpr(`"c"."id", "c"."identity"`).Where(`"c"."purl" <> ''`).
			Scan(ctx, &components); err != nil {
			t.Fatal(err)
		}
		const issues, fixedIssues = 15, 10
		var names []finding.Named
		for i := range issues {
			names = append(names, finding.Named{Identifier: fmt.Sprintf("CVE-2028-%05d", i), Severity: "high"})
		}
		interned, err := finding.NewVulnerabilities(db.DB).Intern(ctx, names)
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Microsecond)
		fixed := at.Add(10 * 24 * time.Hour)
		var rows []finding.Finding
		for i, name := range names {
			if i%2 == 0 {
				if _, err := db.DB.NewUpdate().Table("vulnerability").
					Set(`"published_at" = ?`, at.Add(-20*24*time.Hour)).
					Where(`"id" = ?`, interned[name.Identifier]).Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
			for _, c := range components {
				row := finding.Finding{BuildID: w.Build.ID, Kind: finding.Vulnerable, Visibility: access.Public,
					VulnerabilityID: interned[name.Identifier], ComponentID: c.ID, OccurrenceIdentity: c.Identity,
					OpenedAt: at, OpenedRunID: &opened.ID}
				if i < fixedIssues {
					row.ClosedAt, row.ClosedRunID, row.ClosedBecause = &fixed, &closed.ID, finding.Upgraded
				}
				rows = append(rows, row)
			}
		}
		if err := database.InBatches(ctx, db.DB, rows); err != nil {
			t.Fatal(err)
		}
		dbtest.SettleStatistics(t, db)

		productID := w.Product.ID
		who := access.NewPerson(1, "a reader", false, map[int64][]access.Role{productID: {access.PublicRead}}, 0)
		var took []time.Duration
		var got *finding.Remediation
		for range 5 {
			started := time.Now()
			got, err = store.Remediation(ctx, who, finding.Scope{ProductID: &productID}, time.Time{}, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			took = append(took, time.Since(started))
		}
		slices.Sort(took)
		t.Logf("%s: %d findings; median of five %s; fixed %d, from first sighting %v, from publication %v, undated %v",
			db.Server.Engine, len(rows), took[2].Round(time.Millisecond), got.Fixed, got.TimeToFix,
			got.FromPublication, got.Undated)
		if got.Fixed != fixedIssues {
			t.Fatalf("counted %d fixes, want %d, so this measured something else", got.Fixed, fixedIssues)
		}
	})
}
