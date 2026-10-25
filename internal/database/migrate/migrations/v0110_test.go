// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

// v0110 is the migration v0.11.0 carries v0.10.0's schema across with.
const v0110 = 45

// issuesV0100 is three issues in a v0.10.0 database: one a scan found, one
// somebody recorded a finding of, and one nothing holds.
type issuesV0100 struct{ scanned, recorded, untouched int64 }

func seedIssuesV0100(t *testing.T, ctx context.Context, db *database.DB) issuesV0100 {
	t.Helper()
	declared, err := world.Declare(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
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
	issue := func(name string) int64 {
		t.Helper()
		exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
			VALUES (?, ?, ?, ?, ?)`, name, name, false, at, 0)
		return id(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, name)
	}
	out := issuesV0100{issue("cve-2026-1100"), issue("sonic-2026-123456"), issue("cve-2026-1101")}
	exec(`UPDATE "vulnerability" SET "issue_id" = "id"`)
	exec(`INSERT INTO "component" ("identity", "name", "version", "name_folded", "fold_key", "first_seen_at")
		VALUES (?, ?, ?, ?, ?, ?)`, "libfoo", "libfoo", "1.0", "libfoo", "libfoo", at)
	component := id(`SELECT "id" FROM "component" WHERE "identity" = ?`, "libfoo")
	finding := func(issue int64, kind, visibility string) {
		t.Helper()
		exec(`INSERT INTO "finding" ("target_id", "kind", "visibility", "vulnerability_id", "component_id",
			"place_identity", "urgency", "urgency_exploited", "urgency_exploited_here",
			"urgency_shipped", "opened_at")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			declared.Target.ID, kind, visibility, issue, component, "place-libfoo", 1, false, false, true, at)
	}
	finding(out.scanned, "vulnerability", "public")
	finding(out.recorded, "entered", "private")
	return out
}

// kindsAre asserts each issue says the sort of issue it is.
func (is issuesV0100) kindsAre(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	for issue, want := range map[int64]string{is.scanned: "vulnerability", is.recorded: "flaw", is.untouched: "vulnerability"} {
		var got string
		if err := db.DB.NewRaw(`SELECT "kind" FROM "vulnerability" WHERE "id" = ?`, issue).Scan(ctx, &got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("issue %d is a %q after the upgrade, want %q", issue, got, want)
		}
	}
}

// A v0.10.0 database is upgraded, and every issue it held says what sort of
// issue it is: a flaw where somebody recorded a finding of it here, and a
// published vulnerability otherwise.
func TestAV0100DatabaseUpgradesToV0110(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		issues := seedIssuesV0100(t, ctx, db)
		dbtest.MigrateTo(t, db, v0110)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
		issues.kindsAre(t, ctx, db)
		leaveAtLatest(t, ctx, db)
	})
}

// A start that stopped after adding the column is carried on, and still marks
// the flaws: on MySQL and MariaDB the column commits by itself.
func TestTheV0110UpgradeStepsOverAnIssueKindAlreadyThere(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		issues := seedIssuesV0100(t, ctx, db)
		if _, err := db.ExecContext(ctx,
			`ALTER TABLE "vulnerability" ADD COLUMN "kind" `+kindOf(db)+` DEFAULT 'vulnerability' NOT NULL`); err != nil {
			t.Fatalf("make what a stopped upgrade left: %v", err)
		}
		dbtest.MigrateTo(t, db, v0110)
		issues.kindsAre(t, ctx, db)
		leaveAtLatest(t, ctx, db)
	})
}

// kindOf is how an engine declares a short word.
func kindOf(db *database.DB) string {
	if db.Server.Engine == database.SQLite {
		return "TEXT"
	}
	return "VARCHAR(16)"
}
