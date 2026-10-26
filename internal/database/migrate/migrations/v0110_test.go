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

// acknowledgedV0100 records two reports in a v0.10.0 database: one somebody
// acknowledged late on 3 October, and one nobody answered. It answers the
// person who recorded both.
func acknowledgedV0100(t *testing.T, ctx context.Context, db *database.DB) int64 {
	t.Helper()
	declared, err := world.Declare(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	recorded := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	answered := time.Date(2026, 10, 3, 23, 30, 0, 0, time.UTC)
	report := func(reference string, acknowledged *time.Time) {
		t.Helper()
		var by *int64
		if acknowledged != nil {
			by = &declared.Person.ID
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "flaw_report"
			("reference", "product_id", "summary", "recorded_by", "recorded_at",
			 "acknowledged_at", "acknowledged_by", "found_here")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			reference, declared.Product.ID, "A claim.", declared.Person.ID, recorded,
			acknowledged, by, false).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	report("SONIC-R-2026-111111", &answered)
	report("SONIC-R-2026-222222", nil)
	return declared.Person.ID
}

// sentOnce asserts the acknowledged report holds exactly one message, sent on
// the day it was acknowledged by whoever acknowledged it, and the other none.
func sentOnce(t *testing.T, ctx context.Context, db *database.DB, by int64) {
	t.Helper()
	var rows []struct {
		Reference string    `bun:"reference"`
		Direction string    `bun:"direction"`
		Dated     time.Time `bun:"dated"`
		LoggedBy  int64     `bun:"logged_by"`
	}
	if err := db.DB.NewRaw(`SELECT "fr"."reference", "rm"."direction", "rm"."dated", "rm"."logged_by"
		FROM "report_message" AS "rm" JOIN "flaw_report" AS "fr" ON "fr"."id" = "rm"."flaw_report_id"`).
		Scan(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("the upgrade wrote %d messages, want the one acknowledgement: %+v", len(rows), rows)
	}
	got := rows[0]
	if got.Reference != "SONIC-R-2026-111111" || got.Direction != "sent" ||
		got.Dated.Format(time.DateOnly) != "2026-10-03" || got.LoggedBy != by {
		t.Errorf("the acknowledgement became %+v", got)
	}
}

// A v0.10.0 report's acknowledgement becomes the first message sent to its
// reporter, dated the day it was recorded, by whoever recorded it, and a
// report nobody answered has no correspondence.
func TestAnAcknowledgementBecomesTheFirstMessageSent(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		by := acknowledgedV0100(t, ctx, db)
		dbtest.MigrateTo(t, db, v0110)
		sentOnce(t, ctx, db, by)
		leaveAtLatest(t, ctx, db)
	})
}

// A start that stopped after writing the acknowledgements as messages, and
// before dropping the stamp they came from, writes none of them twice: on
// MySQL and MariaDB the messages commit at the next change to the schema.
func TestAStoppedUpgradeWritesNoAcknowledgementTwice(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		by := acknowledgedV0100(t, ctx, db)
		if err := migrations.StopV0110AfterAcknowledgements(ctx, db); err != nil {
			t.Fatalf("make what a stopped upgrade left: %v", err)
		}
		dbtest.MigrateTo(t, db, v0110)
		sentOnce(t, ctx, db, by)
		leaveAtLatest(t, ctx, db)
	})
}

// A start that stopped after the report step, at a later one, carries on
// over everything the report step made. MySQL and MariaDB adopt the holder
// index for the holder's foreign key and refuse to drop it, so the index is
// made once and never replaced.
func TestTheV0110UpgradeCarriesOnPastItsReportStep(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		by := acknowledgedV0100(t, ctx, db)
		if err := migrations.RunV0110ReportStep(ctx, db); err != nil {
			t.Fatalf("make what a stopped upgrade left: %v", err)
		}
		dbtest.MigrateTo(t, db, v0110)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
		sentOnce(t, ctx, db, by)
		leaveAtLatest(t, ctx, db)
	})
}
