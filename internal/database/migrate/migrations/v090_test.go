// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
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
	product, target, person, issue, other int64
	scans                                 []int64
	root, swss1, swss2, libnl             int64
	layerA, layerB, gap1, gap2            int64
	place, onImage                        string
	// The decisions at the place beneath the image. On the first issue: live
	// at the second build stamp, live at the first and proposed after it, and
	// one that lapsed at the first. On the other issue: approved at the first
	// stamp, and proposed at the second after it.
	atSecond, atFirst, lapsed int64
	approved, proposed        int64
	// A live decision about a finding against the image itself.
	aboutImage int64
}

// seedV080Images writes a build as v0.8.0 stored it across three nightly
// scans: docker-swss stamped master.1 in the first and master.2 from the
// second, each its own component with its own node, libnl beneath both, the
// finding beneath the first closed and the one beneath the second open, a
// finding against the image itself, and an upgrade committed on each stamp's
// fold. Beside it, two layers of one name the build holds at once, and
// docker-gap, shipped in the first scan, gone in the second and back at
// another stamp in the third.
func seedV080Images(t *testing.T, ctx context.Context, db *database.DB) v080World {
	t.Helper()
	declared, err := world.Declare(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	w := v080World{product: declared.Product.ID, target: declared.Target.ID, place: "place-libnl-under-swss",
		onImage: "place-swss"}
	who, err := access.NewStore(db.DB).Ensure(ctx, "image-triager", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.person = who.ID
	at := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	scans := ingest.NewStore(db.DB)
	for i := range 3 {
		rec, outcome, err := scans.Record(ctx, ingest.Arriving{
			TargetID: w.target, ContentHash: "night-" + string(rune('a'+i)),
			BuiltAt: at.Add(time.Duration(i) * 24 * time.Hour), ParserVersion: "test",
		})
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record a scan: %v %v", outcome, err)
		}
		w.scans = append(w.scans, rec.ID)
	}
	s1, s2, s3 := w.scans[0], w.scans[1], w.scans[2]

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
	w.gap1 = stated("pkg:oci/docker-gap@master.1", "docker-gap", "master.1")
	w.gap2 = stated("pkg:oci/docker-gap@master.3", "docker-gap", "master.3")

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
	g1 := node(w.gap1, false, s1, s2, "pkg:oci/docker-gap@master.1")
	g2 := node(w.gap2, false, s3, nil, "pkg:oci/docker-gap@master.3")
	edge(rootNode, g1, s1, s2)
	edge(rootNode, g2, s3, nil)

	exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
		VALUES (?, ?, ?, ?, ?)`, "CVE-2026-0900", "cve-2026-0900", false, at, 0)
	w.issue = id(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, "CVE-2026-0900")
	exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
		VALUES (?, ?, ?, ?, ?)`, "CVE-2026-0901", "cve-2026-0901", false, at, 0)
	w.other = id(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, "CVE-2026-0901")
	exec(`UPDATE "vulnerability" SET "issue_id" = "id"`)
	findingAt := func(issue, component int64, consumer any, place string, closed any) {
		t.Helper()
		exec(`INSERT INTO "finding" ("target_id", "kind", "visibility", "vulnerability_id", "component_id",
			"consumer_id", "place_identity", "urgency", "urgency_exploited", "urgency_exploited_here",
			"urgency_shipped", "last_changed_at", "opened_at", "closed_at")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			w.target, "package", "public", issue, component, consumer, place, 1, false, false, true, at, at, closed)
	}
	for _, issue := range []int64{w.issue, w.other} {
		findingAt(issue, w.libnl, w.swss1, w.place, at.Add(24*time.Hour))
		findingAt(issue, w.libnl, w.swss2, w.place, nil)
	}
	findingAt(w.issue, w.swss2, nil, w.onImage, nil)
	commit := func(fold string) {
		t.Helper()
		exec(`INSERT INTO "upgrade" ("target_id", "fold_key", "from_version", "to_version", "declared_by", "declared_at")
			VALUES (?, ?, ?, ?, ?, ?)`, w.target, fold, "master.1", "master.9", w.person, at)
	}
	// The seed's fold key is the component's identity.
	for _, image := range []int64{w.swss1, w.swss2} {
		var fold string
		if err := db.DB.NewRaw(`SELECT "fold_key" FROM "component" WHERE "id" = ?`, image).Scan(ctx, &fold); err != nil {
			t.Fatal(err)
		}
		commit(fold)
	}
	tag := func(componentID int64) {
		t.Helper()
		exec(`INSERT INTO "finding_tag" ("product_id", "vulnerability_id", "component_id", "tag", "typed", "added_by", "added_at")
			VALUES (?, ?, ?, ?, ?, ?, ?)`, w.product, w.issue, componentID, "waiting", "Waiting", w.person, at)
	}
	tag(w.swss1)
	tag(w.swss2)

	decided := func(issue int64, place, component, consumer, state string, live bool, proposed time.Time) int64 {
		t.Helper()
		exec(`INSERT INTO "claim" ("kind", "proposed_by", "proposed_at", "outcome") VALUES (?, ?, ?, ?)`,
			"finding", w.person, proposed, "not-applicable")
		claim := id(`SELECT MAX("id") FROM "claim"`)
		var key any
		if live {
			key = finding.LiveKey(w.product, issue, place, component, consumer, false)
		}
		var c, u any
		if component != "" {
			c = component
		}
		if consumer != "" {
			u = consumer
		}
		exec(`INSERT INTO "decision" ("claim_id", "product_id", "vulnerability_id", "place_identity", "visibility",
			"component_upstream_version", "consumer_upstream_version", "needs_approval", "state",
			"proposed_by", "proposed_at", "live_key")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			claim, w.product, issue, place, "public", c, u, true, state, w.person, proposed, key)
		return id(`SELECT MAX("id") FROM "decision"`)
	}
	early, late := at.Add(time.Hour), at.Add(25*time.Hour)
	w.lapsed = decided(w.issue, w.place, "3.7.0", "master.1", "lapsed", false, early)
	// Recorded in the order opposite to when each was proposed, so what
	// decides between them is when each was proposed, not which row came
	// first.
	w.atFirst = decided(w.issue, w.place, "3.7.0", "master.1", "approved", true, late)
	w.atSecond = decided(w.issue, w.place, "3.7.0", "master.2", "approved", true, early)
	w.approved = decided(w.other, w.place, "3.7.0", "master.1", "approved", true, early)
	w.proposed = decided(w.other, w.place, "3.7.0", "master.2", "proposed", true, late)
	w.aboutImage = decided(w.issue, w.onImage, "master.2", "", "approved", true, early)
	return w
}

// A v0.8.0 database holding an image rebuilt across two scans is upgraded:
// the two components are one stored by name, the two nodes one across both
// scans, the edges beneath them joined, each build stamp recorded as a version
// the build stated, and the findings, tags, commitments and live decisions
// against it and beneath it pointed at the one image. An image that left and
// came back keeps two nodes. Two layers of one name held at once are left as
// two. The next build stamping the image anew moves nothing but its version.
func TestAV080DatabaseUpgradesItsImagesToTheirNames(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v080)
		w := seedV080Images(t, ctx, db)
		dbtest.MigrateTo(t, db, v090)
		imagesAreMergedV090(t, ctx, db, w)

		t.Run("TheNextRebuildMovesOnlyTheVersion", func(t *testing.T) {
			rec, outcome, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				TargetID: w.target, ContentHash: "night-d",
				BuiltAt: time.Date(2026, 10, 4, 2, 0, 0, 0, time.UTC), ParserVersion: "test",
			})
			if err != nil || outcome != ingest.Accept {
				t.Fatalf("record a scan: %v %v", outcome, err)
			}
			root := graph.Described{Name: "sonic"}
			image := graph.Described{Purl: "pkg:oci/docker-swss@master.4?arch=amd64", Name: "docker-swss",
				Version: "master.4", Container: true}
			gap := graph.Described{Purl: "pkg:oci/docker-gap@master.3", Name: "docker-gap",
				Version: "master.3", Container: true}
			libnl := graph.Described{Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0"}
			layerA := graph.Described{Purl: "pkg:oci/layer@sha256:aaa", Name: "layer", Version: "sha256:aaa"}
			layerB := graph.Described{Purl: "pkg:oci/layer@sha256:bbb", Name: "layer", Version: "sha256:bbb"}
			applied, err := graph.NewStore(db.DB).Apply(ctx, w.target, rec.ID, graph.Snapshot{
				Root: root, Components: []graph.Described{image, gap, libnl, layerA, layerB},
				Dependencies: []graph.Dependency{
					{Parent: root, Child: image}, {Parent: image, Child: libnl}, {Parent: root, Child: gap},
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

// On MySQL and MariaDB a migration's data definition commits as it runs. An
// upgrade whose merge stops part way leaves the image version table and
// nothing else: no version recorded, and every stamp still a component of its
// own. The next start steps over the table and merges whole.
//
// A trigger refusing to remove a component stops the merge at its last step,
// after every other row has been written.
func TestTheV090UpgradeStoppedPartWayMergesWholeOnTheNextStart(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		switch db.Server.Engine {
		case database.MySQL, database.MariaDB:
		default:
			t.Skip("data definition is transactional here, so the whole upgrade is undone with it")
		}
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v080)
		w := seedV080Images(t, ctx, db)
		exec := func(stmt string) {
			t.Helper()
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("%v\n%s", err, stmt)
			}
		}
		exec(`CREATE TRIGGER "stop_v090" BEFORE DELETE ON "component" FOR EACH ROW
			SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'stopped part way'`)
		if err := migrate.UpTo(ctx, db, quiet(), v090); err == nil {
			t.Fatal("the upgrade went through a trigger refusing every removal")
		}
		var versions, stamps int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "image_version"`).Scan(ctx, &versions); err != nil {
			t.Fatal(err)
		}
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "component" WHERE "name" = 'docker-swss' AND "version" <> ''`).
			Scan(ctx, &stamps); err != nil {
			t.Fatal(err)
		}
		if versions != 0 || stamps != 2 {
			t.Errorf("stopped part way, %d image versions and %d stamps of docker-swss remain; "+
				"want none written and both stamps as they were", versions, stamps)
		}
		exec(`DROP TRIGGER "stop_v090"`)
		dbtest.MigrateTo(t, db, v090)
		imagesAreMergedV090(t, ctx, db, w)
		leaveAtLatest(t, ctx, db)
	})
}

// imagesAreMergedV090 checks what the upgrade made of seedV080Images.
func imagesAreMergedV090(t *testing.T, ctx context.Context, db *database.DB, w v080World) {
	t.Helper()
	scan := func(query string, dest ...any) {
		t.Helper()
		if err := db.DB.NewRaw(query).Scan(ctx, dest...); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	named := func(name string) graph.Component {
		t.Helper()
		var images []graph.Component
		if err := db.DB.NewSelect().Model(&images).Where("name = ?", name).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(images) != 1 {
			t.Fatalf("%d components for %s, want one", len(images), name)
		}
		return images[0]
	}
	nodesOf := func(componentID int64) []graph.Node {
		t.Helper()
		var nodes []graph.Node
		if err := db.DB.NewSelect().Model(&nodes).Where("component_id = ?", componentID).
			Order("opened_scan_id").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		return nodes
	}
	versionsOf := func(nodeID int64) []graph.ImageVersion {
		t.Helper()
		var stated []graph.ImageVersion
		if err := db.DB.NewSelect().Model(&stated).Where("iv.node_id = ?", nodeID).
			Order("iv.opened_scan_id").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		return stated
	}

	swss := named("docker-swss")
	stored := graph.Described{Purl: "pkg:oci/docker-swss@master.2?arch=amd64", Name: "docker-swss",
		Version: "master.2"}.AsImage()
	if swss.Version != "" || swss.Purl != "pkg:oci/docker-swss?arch=amd64" || swss.Identity != stored.Identity() ||
		swss.FoldKey != stored.FoldKey() {
		t.Errorf("the image is stored as %+v, want it as the application stores it: %+v", swss, stored)
	}
	nodes := nodesOf(swss.ID)
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
	stated := versionsOf(nodes[0].ID)
	if len(stated) != 2 || stated[0].Version != "master.1" || stated[1].Version != "master.2" ||
		stated[0].ClosedScanID == nil || *stated[0].ClosedScanID != w.scans[1] || stated[1].ClosedScanID != nil ||
		stated[1].Purl != "pkg:oci/docker-swss@master.2?arch=amd64" {
		t.Errorf("the versions the build stated read %+v", stated)
	}

	// Gone in the second scan and back in the third: one component, two nodes,
	// a version on each.
	gap := named("docker-gap")
	gaps := nodesOf(gap.ID)
	if len(gaps) != 2 || gaps[0].ClosedScanID == nil || *gaps[0].ClosedScanID != w.scans[1] ||
		gaps[1].OpenedScanID != w.scans[2] || gaps[1].ClosedScanID != nil {
		t.Errorf("the image that left and came back has nodes %+v, want the two intervals apart", gaps)
	} else if a, b := versionsOf(gaps[0].ID), versionsOf(gaps[1].ID); len(a) != 1 || a[0].Version != "master.1" ||
		len(b) != 1 || b[0].Version != "master.3" {
		t.Errorf("its versions read %+v and %+v, want one on each node", a, b)
	}

	var beneath, against, tags, left, all int
	scan(`SELECT COUNT(*) FROM "finding" WHERE "consumer_id" IN (SELECT "id" FROM "component" WHERE "name" = 'docker-swss')`, &beneath)
	scan(`SELECT COUNT(*) FROM "finding" WHERE "component_id" IN (SELECT "id" FROM "component" WHERE "name" = 'docker-swss')`, &against)
	scan(`SELECT COUNT(*) FROM "finding_tag"`, &tags)
	scan(`SELECT COUNT(*) FROM "component" WHERE "name" = 'layer' AND "version" <> ''`, &left)
	scan(`SELECT COUNT(*) FROM "component"`, &all)
	if beneath != 4 || against != 1 || tags != 1 || left != 2 || all != 6 {
		t.Errorf("%d findings beneath the image, %d against it, %d tags, %d layers by version and %d components; "+
			"want 4, 1, 1, 2 and 6", beneath, against, tags, left, all)
	}

	var commitments []string
	scan(`SELECT "fold_key" FROM "upgrade"`, &commitments)
	if len(commitments) != 1 || commitments[0] != stored.FoldKey() {
		t.Errorf("the commitments read %v, want the one build's on the merged image's fold", commitments)
	}

	var decisions []struct {
		ID        int64   `bun:"id"`
		State     string  `bun:"state"`
		Component *string `bun:"component_upstream_version"`
		Consumer  *string `bun:"consumer_upstream_version"`
		LiveKey   *string `bun:"live_key"`
	}
	if err := db.DB.NewSelect().TableExpr(`"decision"`).
		Column("id", "state", "component_upstream_version", "consumer_upstream_version", "live_key").
		Scan(ctx, &decisions); err != nil {
		t.Fatal(err)
	}
	liveOn := func(issue int64, place, component string) string {
		return finding.LiveKey(w.product, issue, place, component, "", false)
	}
	for _, d := range decisions {
		switch d.ID {
		case w.atFirst:
			if d.State != "approved" || d.Consumer != nil || d.LiveKey == nil || *d.LiveKey != liveOn(w.issue, w.place, "3.7.0") {
				t.Errorf("the decision proposed last reads %+v, want it live on the image by name", d)
			}
		case w.atSecond:
			if d.State != "lapsed" || d.LiveKey != nil {
				t.Errorf("the decision proposed first reads %+v, want it lapsed beside the later one", d)
			}
		case w.approved:
			if d.State != "approved" || d.LiveKey == nil || *d.LiveKey != liveOn(w.other, w.place, "3.7.0") {
				t.Errorf("the approved decision reads %+v, want it live over the one only proposed", d)
			}
		case w.proposed:
			if d.State != "lapsed" || d.LiveKey != nil {
				t.Errorf("the proposed decision reads %+v, want it lapsed beside the approved one", d)
			}
		case w.aboutImage:
			if d.State != "approved" || d.Component != nil || d.LiveKey == nil || *d.LiveKey != liveOn(w.issue, w.onImage, "") {
				t.Errorf("the decision about the image itself reads %+v, want it live on the image by name", d)
			}
		case w.lapsed:
			if d.State != "lapsed" || d.Consumer == nil || *d.Consumer != "master.1" {
				t.Errorf("a decision that had lapsed reads %+v, want it as recorded", d)
			}
		}
	}
}
