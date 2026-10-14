// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// v090 is the migration the untagged release carries v0.8.0's schema across
// with.
const v090 = 43

// v080World is what seedV080Images wrote, by identifier.
type v080World struct {
	product, target, person, issue int64
	scans                          []int64
	root, swss1, swss2, libnl      int64
	layerA, layerB                 int64
	place                          string
	// Three decisions beneath the image: live at the second build stamp,
	// live at the first, and one that lapsed at the first.
	atSecond, atFirst, lapsed int64
}

// seedV080Images writes a build as v0.8.0 stored it across two nightly scans:
// docker-swss stamped master.1 in the first and master.2 in the second, each
// its own component with its own node, libnl beneath both, the finding
// beneath the first closed and the one beneath the second open. Beside it, two
// layers of one name the build holds at once.
func seedV080Images(t *testing.T, ctx context.Context, db *database.DB) v080World {
	t.Helper()
	declared, err := world.Declare(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	w := v080World{product: declared.Product.ID, target: declared.Target.ID, place: "place-libnl-under-swss"}
	who, err := access.NewStore(db.DB).Ensure(ctx, "image-triager", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.person = who.ID
	at := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	scans := ingest.NewStore(db.DB)
	for i := range 2 {
		rec, outcome, err := scans.Record(ctx, ingest.Arriving{
			TargetID: w.target, ContentHash: "night-" + string(rune('a'+i)),
			BuiltAt: at.Add(time.Duration(i) * 24 * time.Hour), ParserVersion: "test",
		})
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record a scan: %v %v", outcome, err)
		}
		w.scans = append(w.scans, rec.ID)
	}
	s1, s2 := w.scans[0], w.scans[1]

	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	id := func(query string, args ...any) int64 {
		t.Helper()
		var out int64
		if err := db.DB.NewRaw(query, args...).Scan(ctx, &out); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
		return out
	}
	component := func(identity, purl, name, version string) int64 {
		t.Helper()
		var p any
		if purl != "" {
			p = purl
		}
		exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "name_folded", "fold_key", "first_seen_at")
			VALUES (?, ?, ?, ?, ?, ?, ?)`, identity, p, name, version, name, identity, at)
		return id(`SELECT "id" FROM "component" WHERE "identity" = ?`, identity)
	}
	// Identified as v0.8.0 identified them, which is as the application
	// identifies a component it does not take for an image.
	stated := func(purl, name, version string) int64 {
		t.Helper()
		return component(graph.Described{Purl: purl, Name: name, Version: version}.Identity(), purl, name, version)
	}
	w.root = stated("", "sonic", "")
	w.swss1 = stated("pkg:oci/docker-swss@master.1?arch=amd64", "docker-swss", "master.1")
	w.swss2 = stated("pkg:oci/docker-swss@master.2?arch=amd64", "docker-swss", "master.2")
	w.libnl = stated("pkg:deb/debian/libnl-3-200@3.7.0", "libnl-3-200", "3.7.0")
	w.layerA = stated("pkg:oci/layer@sha256:aaa", "layer", "sha256:aaa")
	w.layerB = stated("pkg:oci/layer@sha256:bbb", "layer", "sha256:bbb")

	node := func(componentID int64, root bool, opened int64, closed any, purl any) int64 {
		t.Helper()
		exec(`INSERT INTO "graph_node" ("target_id", "component_id", "is_root", "opened_scan_id", "closed_scan_id", "purl")
			VALUES (?, ?, ?, ?, ?, ?)`, w.target, componentID, root, opened, closed, purl)
		return id(`SELECT MAX("id") FROM "graph_node"`)
	}
	edge := func(parent, child, opened int64, closed any) {
		t.Helper()
		exec(`INSERT INTO "graph_edge" ("target_id", "parent_id", "child_id", "kind", "opened_scan_id", "closed_scan_id")
			VALUES (?, ?, ?, ?, ?, ?)`, w.target, parent, child, "", opened, closed)
	}
	rootNode := node(w.root, true, s1, nil, nil)
	n1 := node(w.swss1, false, s1, s2, "pkg:oci/docker-swss@master.1?arch=amd64")
	n2 := node(w.swss2, false, s2, nil, "pkg:oci/docker-swss@master.2?arch=amd64")
	libnl := node(w.libnl, false, s1, nil, "pkg:deb/debian/libnl-3-200@3.7.0")
	la := node(w.layerA, false, s1, nil, "pkg:oci/layer@sha256:aaa")
	lb := node(w.layerB, false, s1, nil, "pkg:oci/layer@sha256:bbb")
	edge(rootNode, n1, s1, s2)
	edge(n1, libnl, s1, s2)
	edge(rootNode, n2, s2, nil)
	edge(n2, libnl, s2, nil)
	edge(rootNode, la, s1, nil)
	edge(rootNode, lb, s1, nil)

	exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
		VALUES (?, ?, ?, ?, ?)`, "CVE-2026-0900", "cve-2026-0900", false, at, 0)
	w.issue = id(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, "CVE-2026-0900")
	exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, w.issue)
	findingAt := func(consumer int64, closed any) {
		t.Helper()
		exec(`INSERT INTO "finding" ("target_id", "kind", "visibility", "vulnerability_id", "component_id",
			"consumer_id", "place_identity", "urgency", "urgency_exploited", "urgency_exploited_here",
			"urgency_shipped", "last_changed_at", "opened_at", "closed_at")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			w.target, "package", "public", w.issue, w.libnl, consumer, w.place, 1, false, false, true, at, at, closed)
	}
	findingAt(w.swss1, at.Add(24*time.Hour))
	findingAt(w.swss2, nil)
	tag := func(componentID int64) {
		t.Helper()
		exec(`INSERT INTO "finding_tag" ("product_id", "vulnerability_id", "component_id", "tag", "typed", "added_by", "added_at")
			VALUES (?, ?, ?, ?, ?, ?, ?)`, w.product, w.issue, componentID, "waiting", "Waiting", w.person, at)
	}
	tag(w.swss1)
	tag(w.swss2)

	decided := func(consumer, state string, live bool) int64 {
		t.Helper()
		exec(`INSERT INTO "claim" ("kind", "proposed_by", "proposed_at", "outcome") VALUES (?, ?, ?, ?)`,
			"finding", w.person, at, "not-applicable")
		claim := id(`SELECT MAX("id") FROM "claim"`)
		var key any
		if live {
			key = finding.LiveKey(w.product, w.issue, w.place, "3.7.0", consumer, false)
		}
		exec(`INSERT INTO "decision" ("claim_id", "product_id", "vulnerability_id", "place_identity", "visibility",
			"component_upstream_version", "consumer_upstream_version", "needs_approval", "state",
			"proposed_by", "proposed_at", "live_key")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			claim, w.product, w.issue, w.place, "public", "3.7.0", consumer, true, state, w.person, at, key)
		return id(`SELECT MAX("id") FROM "decision"`)
	}
	w.lapsed = decided("master.1", "lapsed", false)
	w.atFirst = decided("master.1", "approved", true)
	w.atSecond = decided("master.2", "approved", true)
	return w
}

// A v0.8.0 database holding an image rebuilt across two scans is upgraded:
// the two components are one stored by name, the two nodes one across both
// scans, the edges beneath them joined, each build stamp recorded as a version
// the build stated, and the findings, tags and live decisions beneath it
// pointed at the one image. Two layers of one name held at once are left as
// two. The next build stamping the image anew moves nothing but its version.
func TestAV080DatabaseUpgradesItsImagesToTheirNames(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v080)
		w := seedV080Images(t, ctx, db)
		dbtest.MigrateTo(t, db, v090)

		scan := func(query string, dest ...any) {
			t.Helper()
			if err := db.DB.NewRaw(query).Scan(ctx, dest...); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
		}

		var images []graph.Component
		if err := db.DB.NewSelect().Model(&images).Where("name = ?", "docker-swss").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(images) != 1 {
			t.Fatalf("%d components for docker-swss, want one", len(images))
		}
		swss := images[0]
		stored := graph.Described{Purl: "pkg:oci/docker-swss@master.2?arch=amd64", Name: "docker-swss",
			Version: "master.2"}.AsImage()
		if swss.Version != "" || swss.Purl != "pkg:oci/docker-swss?arch=amd64" || swss.Identity != stored.Identity() ||
			swss.FoldKey != stored.FoldKey() {
			t.Errorf("the image is stored as %+v, want it as the application stores it: %+v", swss, stored)
		}

		var nodes []graph.Node
		if err := db.DB.NewSelect().Model(&nodes).Where("component_id = ?", swss.ID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 1 || nodes[0].OpenedScanID != w.scans[0] || nodes[0].ClosedScanID != nil ||
			nodes[0].Purl != "pkg:oci/docker-swss?arch=amd64" {
			t.Fatalf("the image's nodes are %+v, want one open since the first scan", nodes)
		}
		var edges []graph.Edge
		if err := db.DB.NewSelect().Model(&edges).
			Where("parent_id = ? OR child_id = ?", nodes[0].ID, nodes[0].ID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(edges) != 2 {
			t.Errorf("%d edges at the image, want the one above it and the one below", len(edges))
		}
		for _, e := range edges {
			if e.OpenedScanID != w.scans[0] || e.ClosedScanID != nil {
				t.Errorf("edge %+v is not one edge across both scans", e)
			}
		}
		var stated []graph.ImageVersion
		if err := db.DB.NewSelect().Model(&stated).Order("iv.opened_scan_id").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(stated) != 2 || stated[0].Version != "master.1" || stated[1].Version != "master.2" ||
			stated[0].NodeID != nodes[0].ID || stated[1].NodeID != nodes[0].ID ||
			stated[0].ClosedScanID == nil || *stated[0].ClosedScanID != w.scans[1] || stated[1].ClosedScanID != nil ||
			stated[1].Purl != "pkg:oci/docker-swss@master.2?arch=amd64" {
			t.Errorf("the versions the build stated read %+v", stated)
		}

		var pointed, tags, left int
		scan(`SELECT COUNT(*) FROM "finding" WHERE "consumer_id" IN (SELECT "id" FROM "component" WHERE "name" = 'docker-swss')`, &pointed)
		scan(`SELECT COUNT(*) FROM "finding_tag"`, &tags)
		scan(`SELECT COUNT(*) FROM "component" WHERE "name" = 'layer' AND "version" <> ''`, &left)
		if pointed != 2 || tags != 1 || left != 2 {
			t.Errorf("%d findings beneath the image, %d tags and %d layers by version; want 2, 1 and 2",
				pointed, tags, left)
		}

		var decisions []struct {
			ID       int64   `bun:"id"`
			State    string  `bun:"state"`
			Consumer *string `bun:"consumer_upstream_version"`
			LiveKey  *string `bun:"live_key"`
		}
		if err := db.DB.NewSelect().TableExpr(`"decision"`).
			Column("id", "state", "consumer_upstream_version", "live_key").Scan(ctx, &decisions); err != nil {
			t.Fatal(err)
		}
		for _, d := range decisions {
			switch d.ID {
			case w.atSecond:
				if d.State != "approved" || d.Consumer != nil || d.LiveKey == nil ||
					*d.LiveKey != finding.LiveKey(w.product, w.issue, w.place, "3.7.0", "", false) {
					t.Errorf("the decision made at the second stamp reads %+v, want it live on the image by name", d)
				}
			case w.atFirst:
				if d.State != "lapsed" || d.LiveKey != nil {
					t.Errorf("the decision made at the first stamp reads %+v, want it lapsed beside the later one", d)
				}
			case w.lapsed:
				if d.State != "lapsed" || d.Consumer == nil || *d.Consumer != "master.1" {
					t.Errorf("a decision that had lapsed reads %+v, want it as recorded", d)
				}
			}
		}

		t.Run("TheNextRebuildMovesOnlyTheVersion", func(t *testing.T) {
			rec, outcome, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				TargetID: w.target, ContentHash: "night-c",
				BuiltAt: time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC), ParserVersion: "test",
			})
			if err != nil || outcome != ingest.Accept {
				t.Fatalf("record a scan: %v %v", outcome, err)
			}
			root := graph.Described{Name: "sonic"}
			image := graph.Described{Purl: "pkg:oci/docker-swss@master.3?arch=amd64", Name: "docker-swss",
				Version: "master.3", Container: true}
			libnl := graph.Described{Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0"}
			layerA := graph.Described{Purl: "pkg:oci/layer@sha256:aaa", Name: "layer", Version: "sha256:aaa"}
			layerB := graph.Described{Purl: "pkg:oci/layer@sha256:bbb", Name: "layer", Version: "sha256:bbb"}
			applied, err := graph.NewStore(db.DB).Apply(ctx, w.target, rec.ID, graph.Snapshot{
				Root: root, Components: []graph.Described{image, libnl, layerA, layerB},
				Dependencies: []graph.Dependency{
					{Parent: root, Child: image}, {Parent: image, Child: libnl},
					{Parent: root, Child: layerA}, {Parent: root, Child: layerB},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if want := (graph.Applied{VersionsOpened: 1, VersionsClosed: 1}); applied != want {
				t.Errorf("the first rebuild after the upgrade wrote %+v, want %+v", applied, want)
			}
		})

		t.Run("TheDeclarationsAreTheTablesTheMigrationsBuild", func(t *testing.T) {
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV090(db.Server.Engine))
		})
		leaveAtLatest(t, ctx, db)
	})
}
