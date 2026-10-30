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
	declared := worldBeforeV0110(t, ctx, db)
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
			declared.Build.ID, kind, visibility, issue, component, "place-libfoo", 1, false, false, true, at)
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

// findingsAreOnTheirBranch asserts every finding the database held, of which
// there were seeded, still names the build it was filed against, read
// through the tables a branch or tag and a build are renamed to.
func findingsAreOnTheirBranch(t *testing.T, ctx context.Context, db *database.DB, seeded int) {
	t.Helper()
	var named []string
	if err := db.DB.NewRaw(`SELECT "bt"."name" FROM "finding" AS "f"
		JOIN "build" AS "b" ON "b"."id" = "f"."build_id"
		JOIN "branch_or_tag" AS "bt" ON "bt"."id" = "b"."branch_or_tag_id"`).Scan(ctx, &named); err != nil {
		t.Fatal(err)
	}
	if seeded == 0 {
		t.Fatal("no finding was seeded, so this checked nothing")
	}
	if len(named) != seeded {
		t.Fatalf("%d findings are read through their build, want all %d", len(named), seeded)
	}
	for _, each := range named {
		if each != world.BranchName {
			t.Errorf("a finding is on %q after the upgrade, want %q", each, world.BranchName)
		}
	}
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
	declared := worldBeforeV0110(t, ctx, db)
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

// A stopped upgrade can leave the report step's tables made without the
// indexes made after them, and its columns changed without the holder's
// foreign key. Starting again makes what is missing.
func TestTheV0110UpgradeMakesWhatAStopLeftUnmade(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		if err := migrations.RunV0110ReportStep(ctx, db); err != nil {
			t.Fatalf("make what a stopped upgrade left: %v", err)
		}
		// On MySQL and MariaDB the index serves a foreign key, so the key
		// goes with it and comes back alone, as it stands where the table
		// was made and the index was not.
		var unmade []string
		switch db.Server.Engine {
		case database.MySQL, database.MariaDB:
			unmade = []string{
				`ALTER TABLE "report_message" DROP FOREIGN KEY "report_message_report_fk"`,
				`DROP INDEX "report_message_log_idx" ON "report_message"`,
				`ALTER TABLE "report_message" ADD CONSTRAINT "report_message_report_fk"
					FOREIGN KEY ("flaw_report_id") REFERENCES "flaw_report"("id")`,
				`ALTER TABLE "flaw_report" DROP FOREIGN KEY "flaw_report_holder_fk"`,
			}
		case database.Postgres:
			unmade = []string{
				`DROP INDEX "report_message_log_idx"`,
				`ALTER TABLE "flaw_report" DROP CONSTRAINT "flaw_report_holder_fk"`,
			}
		default:
			unmade = []string{`DROP INDEX "report_message_log_idx"`}
		}
		for _, stmt := range unmade {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
		}
		dbtest.MigrateTo(t, db, v0110)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// seedReportsV0100 writes the reports v0.10.0 wrote beside issues: one on a
// flaw recorded by hand with no reported problem of its own, one on a
// published vulnerability, and one a flaw was recorded from, which carries the
// reporter's own words. The flaws carry the summary somebody here wrote, and
// the vulnerability its publisher's description.
func seedReportsV0100(t *testing.T, ctx context.Context, db *database.DB, issues issuesV0100) {
	t.Helper()
	declared := worldBeforeV0110(t, ctx, db)
	at := time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	// The third report's issue is a flaw of its own, made one recorded here
	// the way the issues seed makes its recorded one, so the issues seed's
	// untouched issue stays untouched.
	exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
		VALUES (?, ?, ?, ?, ?)`, "sonic-2026-654321", "sonic-2026-654321", false, at, 0)
	var other int64
	if err := db.DB.NewRaw(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, "sonic-2026-654321").
		Scan(ctx, &other); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, other)
	exec(`INSERT INTO "finding" ("target_id", "kind", "visibility",
		"vulnerability_id", "component_id", "place_identity", "urgency", "urgency_exploited",
		"urgency_exploited_here", "urgency_shipped", "opened_at")
		SELECT "target_id", "kind", "visibility", ?, "component_id", 'place-other', "urgency",
			"urgency_exploited", "urgency_exploited_here", "urgency_shipped", "opened_at"
		FROM "finding" WHERE "vulnerability_id" = ?`, other, issues.recorded)
	for issue, words := range map[int64]string{
		issues.recorded: "The flaw as somebody here described it.",
		issues.scanned:  "The publisher's description.",
		other:           "A flaw recorded here.",
	} {
		exec(`UPDATE "vulnerability" SET "description" = ? WHERE "id" = ?`, words, issue)
	}
	for reference, seeded := range map[string]struct {
		issue   int64
		problem string
	}{
		"SONIC-R-2026-333333": {issues.recorded, ""},
		"SONIC-R-2026-444444": {issues.scanned, ""},
		"SONIC-R-2026-555555": {other, "The reporter's own words."},
	} {
		exec(`INSERT INTO "flaw_report"
			("reference", "product_id", "vulnerability_id", "summary", "recorded_by", "recorded_at",
			 "evaluated_at", "evaluated_by", "found_here")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			reference, declared.Product.ID, seeded.issue, seeded.problem, declared.Person.ID, at, at,
			declared.Person.ID, false)
	}
}

// reportedProblemsAre asserts the report on the flaw recorded by hand carries
// the flaw's summary as its reported problem, under the column's new name,
// and the other two are left as they were.
func reportedProblemsAre(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	for reference, want := range map[string]string{
		"SONIC-R-2026-333333": "The flaw as somebody here described it.",
		"SONIC-R-2026-444444": "",
		"SONIC-R-2026-555555": "The reporter's own words.",
	} {
		var got *string
		if err := db.DB.NewRaw(`SELECT "reported_problem" FROM "flaw_report" WHERE "reference" = ?`,
			reference).Scan(ctx, &got); err != nil {
			t.Fatal(err)
		}
		said := ""
		if got != nil {
			said = *got
		}
		if said != want {
			t.Errorf("report %s reports %q after the upgrade, want %q", reference, said, want)
		}
	}
}

// One v0.10.0 database per engine holds every seed an upgrade that does not
// stop is checked against, and is upgraded once; each subtest pins one thing
// the upgrade does to it. Migrating a fresh database to v0.10.0 is most of
// what an upgrade test costs, so one build serves them all. The seeds share
// the default world, and each writes identities of its own, so no seed
// changes what another's subtest reads. The subtests that write run last.
func TestAV0100DatabaseHoldingEverySeedUpgradesToV0110(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		issues := seedIssuesV0100(t, ctx, db)
		acknowledgedBy := acknowledgedV0100(t, ctx, db)
		seedReportsV0100(t, ctx, db, issues)
		triage := seedTriageV0100(t, ctx, db)
		incidents := seedIncidentsV0100(t, ctx, db)
		rules := seedRulesV0100(t, ctx, db)
		words := seedWordsV0100(t, ctx, db)
		role := seedRoleV0100(t, ctx, db)
		var findings int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "finding"`).Scan(ctx, &findings); err != nil {
			t.Fatal(err)
		}
		dbtest.MigrateTo(t, db, v0110)

		// Every issue says what sort of issue it is: a flaw where somebody
		// recorded a finding of it here, and a published vulnerability
		// otherwise.
		t.Run("AV0100DatabaseUpgradesToV0110", func(t *testing.T) {
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
			issues.kindsAre(t, ctx, db)
			findingsAreOnTheirBranch(t, ctx, db, findings)
		})
		// A report's acknowledgement becomes the first message sent to its
		// reporter, dated the day it was recorded, by whoever recorded it,
		// and a report nobody answered has no correspondence.
		t.Run("AnAcknowledgementBecomesTheFirstMessageSent", func(t *testing.T) {
			sentOnce(t, ctx, db, acknowledgedBy)
		})
		// The report beside a flaw recorded by hand, with no reported problem
		// of its own, carries the flaw's summary as its reported problem. A
		// report on a published vulnerability is left as it was: that
		// issue's description is the publisher's, never what the reporter
		// said.
		t.Run("AHandRecordedFlawsReportCarriesItsSummaryAsItsReportedProblem", func(t *testing.T) {
			reportedProblemsAre(t, ctx, db)
		})
		// A claim and everything beside it reads back under v0.11.0's names
		// in the shape the release declares.
		t.Run("AV0100DatabaseTakesTheV0110TriageNames", func(t *testing.T) {
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
			triage.renamedAs(t, ctx, db)
		})
		// A standing rule, a supplier, a label and VEX each way read back
		// under v0.11.0's names in the shape the release declares.
		t.Run("AV0100DatabaseTakesTheV0110RuleNames", func(t *testing.T) {
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
			rules.renamedAs(t, ctx, db)
		})
		// Every stored word v0.11.0 renames reads in v0.11.0's spelling.
		t.Run("AV0100DatabaseTakesTheV0110StoredWords", func(t *testing.T) {
			wordsRenamed(t, ctx, db, words)
		})
		// An incident, its windows and everything beside them read back
		// under v0.11.0's names in the shape the release declares, with new
		// rows numbered after the old.
		t.Run("AV0100DatabaseTakesTheV0110IncidentNames", func(t *testing.T) {
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
			incidents.renamedAs(t, ctx, db)
			incidents.numberedAfter(t, ctx, db)
		})
		t.Run("EveryRoleColumnHoldsTheLongestRoleAfterTheV0110Upgrade", func(t *testing.T) {
			role.holdsTheLongest(t, ctx, db)
		})
		leaveAtLatest(t, ctx, db)
	})
}
