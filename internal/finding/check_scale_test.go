// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What checking a replaced inventory costs on a real image: the two
// inventories read back from the graph's intervals, and the findings the
// check writes.
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
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// checkedImage is the full-size image's build with its first inventory
// replaced and checked, and what the check took. The replacement moves every
// hundredth package and the kernel; every package of the replaced inventory
// carries one issue published while it was current.
func checkedImage(t *testing.T, doc *sbom.Document, db *database.DB) *world.World {
	t.Helper()
	ctx := t.Context()
	w := world.New(t, db)
	store := finding.NewStore(db.DB)
	first := doc.Snapshot(graph.Described{Name: "sonic", Version: "1.0"})
	arrived := time.Now().UTC().Add(-10 * 24 * time.Hour).Truncate(time.Second)
	replacedAt := arrived.Add(3 * 24 * time.Hour)

	current := append([]graph.Described(nil), first.Components...)
	moved := map[string]graph.Described{}
	for n, c := range first.Components {
		if c.Purl == "" || (n%100 != 0 && !strings.Contains(c.Purl, "/linux-image-")) {
			continue
		}
		bumped := c
		bumped.Version = c.Version + "+moved"
		bumped.Purl = strings.Replace(c.Purl, "@"+c.Version, "@"+bumped.Version, 1)
		if bumped.UpstreamVersion != "" {
			bumped.UpstreamVersion += "+moved"
		}
		moved[c.Purl] = bumped
		current[n] = bumped
	}
	second := graph.Snapshot{Root: first.Root, Components: current}
	for _, d := range first.Dependencies {
		parent, child := d.Parent, d.Child
		if m, ok := moved[parent.Purl]; ok {
			parent = m
		}
		if m, ok := moved[child.Purl]; ok {
			child = m
		}
		second.Dependencies = append(second.Dependencies, graph.Dependency{Parent: parent, Child: child, Kind: d.Kind})
	}

	var scans []int64
	for i, snap := range []graph.Snapshot{first, second} {
		scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
			BuildID: w.Build.ID, ContentHash: fmt.Sprintf("scan-%d", i), BuiltAt: arrived.Add(time.Duration(i) * 72 * time.Hour),
			ParserVersion: "measure",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := world.ApplyGraph(ctx, db.DB, w.Build.ID, scan.ID, snap); err != nil {
			t.Fatal(err)
		}
		scans = append(scans, scan.ID)
	}

	var reported []finding.Reported
	var names []finding.Named
	for n, c := range first.Components {
		if c.Purl == "" {
			continue
		}
		issue := finding.Named{Identifier: fmt.Sprintf("CVE-2027-%05d", n), Severity: "high"}
		reported = append(reported, finding.Reported{Issue: issue, Component: c})
		names = append(names, issue)
	}
	if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, names); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.NewUpdate().Table("vulnerability").
		Set(`"published_at" = ?`, arrived.Add(24*time.Hour)).
		Set(`"dates_asked_at" = ?`, arrived.Add(24*time.Hour)).
		Where(`"identifier" LIKE ?`, "CVE-2027-%").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	// Analyzed without the layout SettleStatistics prints, which a server
	// cannot report while the finding table is still empty.
	if _, err := database.AnalyzeEveryTable(ctx, db); err != nil {
		t.Fatal(err)
	}

	read := time.Now()
	before, err := graph.NewStore(db.DB).ComponentsAt(ctx, w.Build.ID, graph.AtScan(scans[0]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := graph.NewStore(db.DB).ComponentsAt(ctx, w.Build.ID, graph.AtScan(scans[1])); err != nil {
		t.Fatal(err)
	}
	reading := time.Since(read)

	run, err := store.Begin(ctx, finding.Run{BuildID: w.Build.ID, Scanner: "measure", RanHere: true,
		CheckedScanID: &scans[0]})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	checked, err := store.CheckReplaced(ctx, finding.Replaced{
		BuildID: w.Build.ID, ScanID: scans[0], ReplacementID: scans[1],
		ArrivedAt: arrived, ReplacedAt: replacedAt,
	}, run.ID, reported)
	if err != nil {
		t.Fatal(err)
	}
	checking := time.Since(started)
	t.Logf("%s: %d components, %d moved, %d reports dated, %d findings recorded; "+
		"both inventories read in %s, the check in %s",
		db.Server.Engine, len(before), len(moved), checked.Dated, checked.Recorded,
		reading.Round(time.Millisecond), checking.Round(time.Millisecond))
	if checked.Recorded == 0 {
		t.Fatal("the check recorded nothing, so this measured nothing")
	}
	return w
}

func TestMeasureTheCheckOfAReplacedInventory(t *testing.T) {
	doc := fullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		checkedImage(t, doc, db)
	})
}

// Remediation's figures over a build holding a check's matches beside ordinary
// history: a run opening fifteen issues at every component of the replacement,
// a third of them closed by a later run as upgraded.
func TestMeasureRemediationBesideACheck(t *testing.T) {
	doc := fullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := checkedImage(t, doc, db)
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
		const issues = 15
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
			for n, c := range components {
				row := finding.Finding{BuildID: w.Build.ID, Kind: finding.Vulnerable, Visibility: access.Public,
					VulnerabilityID: interned[name.Identifier], ComponentID: c.ID, OccurrenceIdentity: c.Identity,
					OpenedAt: at, OpenedRunID: &opened.ID}
				if (n+i)%3 == 0 {
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
		t.Logf("%s: %d findings; remediation (fixed %d, opened %d) median of five %s",
			db.Server.Engine, len(rows), got.Fixed, got.Opened, took[2].Round(time.Millisecond))
		if got.Opened == 0 {
			t.Fatal("nothing opened, so this measured nothing")
		}
	})
}
