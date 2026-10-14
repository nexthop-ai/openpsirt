// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

package migrations_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// The v0.9.0 upgrade on a database the size ten nightly SONiC builds leave:
// 34 images restamped every night over 600 packages, 1,632,000 findings and
// 204,000 edges beneath them. PostgreSQL alone, because that is what the
// deployment it was written for runs, and the rows are made by the server
// rather than sent, which is the only way to make this many in a test's time.
func TestMeasureTheV090UpgradeOnTenNightlyBuilds(t *testing.T) {
	dbtest.Only(t, database.Postgres, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v080)
		d, err := world.Declare(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		target := d.Target.ID
		var scans []int64
		at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		for i := range 10 {
			rec, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{TargetID: target,
				ContentHash: fmt.Sprintf("h%d", i), BuiltAt: at.Add(time.Duration(i) * time.Hour), ParserVersion: "t"})
			if err != nil {
				t.Fatal(err)
			}
			scans = append(scans, rec.ID)
		}
		exec := func(q string, args ...any) {
			t.Helper()
			if _, err := db.ExecContext(ctx, q, args...); err != nil {
				t.Fatalf("%v\n%s", err, q)
			}
		}
		// 600 packages, each beneath every image.
		exec(`INSERT INTO "component" ("identity","purl","name","version","name_folded","fold_key","first_seen_at")
			SELECT 'p'||g, 'pkg:deb/debian/p'||g||'@1', 'p'||g, '1', 'p'||g, 'f'||g, now() FROM generate_series(1,600) g`)
		// 34 images, each stamped ten times, as v0.8.0 stored them.
		exec(`INSERT INTO "component" ("identity","purl","name","version","name_folded","fold_key","first_seen_at")
			SELECT 'i'||i||'v'||v, 'pkg:oci/docker-'||i||'@master.'||v||'?arch=amd64', 'docker-'||i, 'master.'||v, 'docker-'||i, 'fi'||i||'v'||v, now()
			FROM generate_series(1,34) i, generate_series(1,10) v`)
		exec(`INSERT INTO "graph_node" ("target_id","component_id","is_root","opened_scan_id","purl")
			SELECT ` + fmt.Sprint(target) + `, c.id, false, ` + fmt.Sprint(scans[0]) + `, c.purl FROM "component" c WHERE c.identity LIKE 'p%'`)
		// Each image's node closes at the scan the next stamp opens.
		exec(`INSERT INTO "graph_node" ("target_id","component_id","is_root","opened_scan_id","closed_scan_id","purl")
			SELECT ` + fmt.Sprint(target) + `, c.id, false, ` + fmt.Sprint(scans[0]-1) + `+v, CASE WHEN v < 10 THEN ` + fmt.Sprint(scans[0]) + `+v END, c.purl
			FROM "component" c, generate_series(1,10) v WHERE c.identity LIKE 'i%v'||v`)
		exec(`INSERT INTO "graph_edge" ("target_id","parent_id","child_id","kind","opened_scan_id","closed_scan_id")
			SELECT ` + fmt.Sprint(target) + `, n.id, pn.id, '', n.opened_scan_id, n.closed_scan_id
			FROM "graph_node" n JOIN "component" c ON c.id = n.component_id AND c.identity LIKE 'i%'
			CROSS JOIN "graph_node" pn JOIN "component" pc ON pc.id = pn.component_id AND pc.identity LIKE 'p%'`)
		exec(`INSERT INTO "vulnerability" ("identifier","identifier_folded","exploited","first_seen_at","issue_id") VALUES ('CVE-1','cve-1',false,now(),0)`)
		exec(`UPDATE "vulnerability" SET "issue_id" = "id"`)
		// Eight findings for every package beneath every stamp, the last open.
		exec(`INSERT INTO "finding" ("target_id","kind","visibility","vulnerability_id","component_id","consumer_id","place_identity",
			"urgency","urgency_exploited","urgency_exploited_here","urgency_shipped","last_changed_at","opened_at","closed_at")
			SELECT ` + fmt.Sprint(target) + `, 'package', 'public', (SELECT min(id) FROM "vulnerability"), pc.id, c.id, md5(c.name||pc.name),
				1, false, false, true, now(), now(), CASE WHEN c.version <> 'master.10' THEN now() END
			FROM "component" c CROSS JOIN "component" pc CROSS JOIN generate_series(1,8) k
			WHERE c.identity LIKE 'i%' AND pc.identity LIKE 'p%'`)
		if _, err := access.NewStore(db.DB).Ensure(ctx, "measurer", "", nil, nil); err != nil {
			t.Fatal(err)
		}
		// Six live decisions at every place beneath the image as the last
		// stamp holds it: 122,400, each keyed on that stamp, and every one
		// of them re-keyed by the upgrade.
		exec(`INSERT INTO "vulnerability" ("identifier","identifier_folded","exploited","first_seen_at","issue_id")
			SELECT 'CVE-D-'||k, 'cve-d-'||k, false, now(), 0 FROM generate_series(1,6) k`)
		exec(`UPDATE "vulnerability" SET "issue_id" = "id"`)
		exec(`INSERT INTO "claim" ("kind","proposed_by","proposed_at","outcome")
			SELECT 'finding', MIN("id"), now(), 'not-applicable' FROM "person"`)
		exec(`INSERT INTO "decision" ("claim_id","product_id","vulnerability_id","place_identity","visibility",
				"component_upstream_version","consumer_upstream_version","needs_approval","state",
				"proposed_by","proposed_at","live_key")
			SELECT (SELECT MIN("id") FROM "claim"), ` + fmt.Sprint(d.Product.ID) + `, v.id, md5(c.name||pc.name), 'public',
				'1', c.version, true, 'approved', (SELECT MIN("id") FROM "person"), now(),
				md5(v.id||c.name||pc.name)
			FROM "component" c CROSS JOIN "component" pc CROSS JOIN "vulnerability" v
			WHERE c.identity LIKE 'i%v10' AND pc.identity LIKE 'p%' AND v.identifier LIKE 'CVE-D-%'`)
		exec(`ANALYZE`)
		var findings, edges, decisions int
		_ = db.DB.NewRaw(`SELECT COUNT(*) FROM "finding"`).Scan(ctx, &findings)
		_ = db.DB.NewRaw(`SELECT COUNT(*) FROM "decision"`).Scan(ctx, &decisions)
		_ = db.DB.NewRaw(`SELECT COUNT(*) FROM "graph_edge"`).Scan(ctx, &edges)
		start := time.Now()
		dbtest.MigrateTo(t, db, v090)
		t.Logf("merged %d findings, %d edges and %d decisions in %s", findings, edges, decisions, time.Since(start))
		_ = db.DB.NewRaw(`SELECT COUNT(*) FROM "graph_edge"`).Scan(ctx, &edges)
		var comps, versions int
		_ = db.DB.NewRaw(`SELECT COUNT(*) FROM "component" WHERE "name" LIKE 'docker-%'`).Scan(ctx, &comps)
		_ = db.DB.NewRaw(`SELECT COUNT(*) FROM "image_version"`).Scan(ctx, &versions)
		t.Logf("after: %d edges, %d image components, %d versions", edges, comps, versions)
		leaveAtLatest(t, ctx, db)
	})
}
