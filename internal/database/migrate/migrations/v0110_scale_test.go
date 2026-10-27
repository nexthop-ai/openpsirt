// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

package migrations_test

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// The rows a measured v0.10.0 database holds in each table it fills, and the
// rows among them holding a stored word the upgrade rewrites. The rewritten
// rows are the same in both, so whatever grows between the two is work on
// rows the upgrade has no reason to read.
const (
	smallV0110     = 1_000
	largeV0110     = 1_000_000
	rewrittenV0110 = 1_000
)

// growthV0110 is how many times longer a phase may take on the large
// database than on the small one, and floorV0110 the shortest time a ratio is
// taken over.
//
// A phase whose work is the same at both sizes measures the same within the
// noise of a shared host, which runs well under half again. A phase reading
// every row of a table it changes takes about a thousand times longer on a
// thousand times the rows, and still twice as long where a fixed cost is
// most of the small run. Twice is past the noise and far below any row work.
// A phase under half a second on a million rows a table is not a stall
// whatever its ratio: SQLite's renames take milliseconds, which a scheduler
// pause doubles, and a decision's kind is read from its table, which is under
// half a second on a million decisions on every engine. A notification's link
// is matched by its prefix, which no index serves: 734 ms on a million
// notifications on MySQL, inside twice the floor.
const (
	growthV0110 = 2
	floorV0110  = 500 * time.Millisecond
)

// The v0.11.0 upgrade's renames and stored words, timed on a v0.10.0 database
// holding a thousand rows in each table it fills and on one holding a million.
// Neither may grow with the rows: a rename changes the catalog alone, and a
// stored word is found through an index on the column holding it. The rest
// of the upgrade builds indexes, which grows with the rows by its nature, and
// is logged for the upgrade note rather than held.
//
// Timed alone with OPENPSIRT_TEST_ENGINES naming one engine: four engines
// seeding a million rows a table at once on one host time each other.
func TestMeasureTheV0110UpgradeAgainstTheRowsItHolds(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		small := timeUpgradeV0110(t, db, smallV0110)
		large := timeUpgradeV0110(t, db, largeV0110)
		for _, phase := range []string{"renames", "stored words", "changes"} {
			t.Logf("%s: %s at %d rows, %s at %d rows", phase,
				small[phase], smallV0110, large[phase], largeV0110)
		}
		held := []string{"renames", "stored words"}
		if db.Server.Engine == database.SQLite {
			// SQLite renames an index by building it again, so its renames
			// grow with the rows by design. It is a development database.
			held = []string{"stored words"}
		}
		for _, phase := range held {
			if grewV0110(small[phase], large[phase]) {
				t.Errorf("the %s took %s at %d rows and %s at %d rows: the phase grows with the rows",
					phase, small[phase], smallV0110, large[phase], largeV0110)
			}
		}
	})
}

// grewV0110 reports whether the large run took more than growthV0110 times
// the small one, each taken as at least floorV0110.
func grewV0110(small, large time.Duration) bool {
	return max(large, floorV0110) > growthV0110*max(small, floorV0110)
}

// timeUpgradeV0110 builds a v0.10.0 database holding rows rows in each table
// it fills, upgrades it to v0.11.0, and answers how long each phase took, as
// the upgrade logs it.
func timeUpgradeV0110(t *testing.T, db *database.DB, rows int) map[string]time.Duration {
	t.Helper()
	ctx := t.Context()
	dbtest.Empty(t, db)
	dbtest.MigrateTo(t, db, v0100)
	start := time.Now()
	seedRowsV0100(t, ctx, db, rows)
	dbtest.SettleStatistics(t, db)
	t.Logf("seeded %d rows a table in %s", rows, time.Since(start))
	phases := &phaseLog{took: map[string]time.Duration{}}
	start = time.Now()
	if err := migrate.UpTo(ctx, db, slog.New(phases), v0110); err != nil {
		t.Fatalf("upgrade %d rows a table: %v", rows, err)
	}
	t.Logf("upgraded %d rows a table in %s", rows, time.Since(start))
	for _, phase := range []string{"renames", "stored words", "changes"} {
		if _, ok := phases.took[phase]; !ok {
			t.Fatalf("the upgrade logged no time for its %s", phase)
		}
	}
	return phases.took
}

// seedRowsV0100 fills a v0.10.0 database, written with v0.10.0's names, with
// rows findings, claims, rows of a claim at a place, notifications and jobs.
// rewrittenV0110 of the claims are bulk claims and as many notifications are
// of a kind the upgrade renames; every other row holds a word it keeps.
func seedRowsV0100(t *testing.T, ctx context.Context, db *database.DB, rows int) {
	t.Helper()
	at := time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)
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
	exec(`INSERT INTO "party" ("kind") VALUES (?)`, "person")
	party := id(`SELECT MAX("id") FROM "party"`)
	exec(`INSERT INTO "person" ("party_id", "identity", "is_admin", "is_bootstrap", "admin_derived", "audits",
		"audits_derived", "email_source", "digest", "digest_unassigned", "created_at")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		party, "measurer", false, false, false, false, false, "", false, false, at)
	person := id(`SELECT MAX("id") FROM "person"`)
	exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "measured", "Measured", at)
	product := id(`SELECT MAX("id") FROM "product"`)
	exec(`INSERT INTO "stream" ("product_id", "name", "display_name", "kind", "created_at") VALUES (?, ?, ?, ?, ?)`,
		product, "main", "main", "branch", at)
	stream := id(`SELECT MAX("id") FROM "stream"`)
	exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
		VALUES (?, ?, ?, ?, ?)`, product, "image", "Image", true, at)
	variant := id(`SELECT MAX("id") FROM "variant"`)
	exec(`INSERT INTO "target" ("stream_id", "variant_id", "created_at") VALUES (?, ?, ?)`, stream, variant, at)
	target := id(`SELECT MAX("id") FROM "target"`)
	exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
		VALUES (?, ?, ?, ?, ?)`, "CVE-2026-1", "cve-2026-1", false, at, 0)
	issue := id(`SELECT MAX("id") FROM "vulnerability"`)
	exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, issue)
	exec(`INSERT INTO "component" ("identity", "name", "version", "fold_key", "first_seen_at")
		VALUES (?, ?, ?, ?, ?)`, "libfoo@1", "libfoo", "1", "libfoo", at)
	component := id(`SELECT MAX("id") FROM "component"`)

	// numbered is the rows numbered from zero, made by the server: a
	// thousand from a recursive count, crossed with itself for more.
	numbered := `WITH RECURSIVE "d" ("i") AS (SELECT 0 UNION ALL SELECT "i" + 1 FROM "d" WHERE "i" < 999)
		SELECT "a"."i" AS "n" FROM "d" AS "a"`
	if rows > 1_000 {
		numbered = fmt.Sprintf(`WITH RECURSIVE "d" ("i") AS (SELECT 0 UNION ALL SELECT "i" + 1 FROM "d" WHERE "i" < 999)
		SELECT "a"."i" * 1000 + "b"."i" AS "n" FROM "d" AS "a" CROSS JOIN "d" AS "b"
		WHERE "a"."i" * 1000 + "b"."i" < %d`, rows)
	}

	exec(`INSERT INTO "finding" ("target_id", "kind", "visibility", "vulnerability_id", "component_id",
		"place_identity", "urgency", "urgency_exploited", "urgency_exploited_here", "urgency_shipped", "opened_at")
		SELECT ?, 'package', 'public', ?, ?, CONCAT('place-', "n"."n"), 1, ?, ?, ?, ?
		FROM (`+numbered+`) AS "n"`, target, issue, component, false, false, true, at)
	exec(`INSERT INTO "claim" ("kind", "proposed_by", "proposed_at", "outcome")
		SELECT CASE WHEN "n"."n" < ? THEN 'together' ELSE 'finding' END, ?, ?, 'not-applicable'
		FROM (`+numbered+`) AS "n"`, rewrittenV0110, person, at)
	claim := id(`SELECT MIN("id") FROM "claim"`)
	exec(`INSERT INTO "decision" ("claim_id", "product_id", "vulnerability_id", "place_identity", "visibility",
		"needs_approval", "state", "proposed_by", "proposed_at")
		SELECT ?, ?, ?, CONCAT('place-', "n"."n"), 'public', ?, 'approved', ?, ?
		FROM (`+numbered+`) AS "n"`, claim, product, issue, true, person, at)

	// The renamed kinds take turns over the rewritten rows, so each is found
	// and changed whatever its share.
	renamed := migrations.NotificationKindsRenamedV0110()
	kind := "CASE"
	for i, from := range renamed {
		kind += fmt.Sprintf(` WHEN "n"."n" < ? AND "n"."n" %% %d = %d THEN '%s'`, len(renamed), i, from)
	}
	kind += ` ELSE 'assigned' END`
	args := []any{person}
	for range renamed {
		args = append(args, rewrittenV0110)
	}
	args = append(args, false, at)
	exec(`INSERT INTO "notification" ("person_id", "kind", "lifetime", "about", "body", "link", "private",
		"together", "attempts", "created_at")
		SELECT ?, `+kind+`, 'event', CONCAT('about-', "n"."n"), 'Something happened.', '/', ?, '', 0, ?
		FROM (`+numbered+`) AS "n"`, args...)
	exec(`INSERT INTO "job" ("kind", "reference", "state", "attempts", "max_attempts", "run_after",
		"created_at", "updated_at")
		SELECT 'measured', CONCAT('job-', "n"."n"), 'done', 1, 1, ?, ?, ?
		FROM (`+numbered+`) AS "n"`, at, at, at)
}

// phaseLog is a log handler keeping the time each phase of an upgrade took.
type phaseLog struct {
	mu   sync.Mutex
	took map[string]time.Duration
}

func (p *phaseLog) Enabled(context.Context, slog.Level) bool { return true }

func (p *phaseLog) Handle(_ context.Context, r slog.Record) error {
	var phase string
	var took time.Duration
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "phase":
			phase = a.Value.String()
		case "took":
			took = a.Value.Duration()
		}
		return true
	})
	if phase != "" {
		p.mu.Lock()
		p.took[phase] = took
		p.mu.Unlock()
	}
	return nil
}

func (p *phaseLog) WithAttrs([]slog.Attr) slog.Handler { return p }
func (p *phaseLog) WithGroup(string) slog.Handler      { return p }
