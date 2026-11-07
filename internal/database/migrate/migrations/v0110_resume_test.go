// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// The former tests a stopped start of the v0.11.0 upgrade is checked by, each
// a subtest of the one below under its own name.
const (
	renamesResume     = "AnUpgradeStoppedPartWayThroughItsRenamesResumes"
	ruleRenamesResume = "AnUpgradeStoppedPartWayThroughTheRuleRenamesResumes"
	storedWordsResume = "AnUpgradeStoppedPartWayThroughItsStoredWordsResumes"
	acknowledgedOnce  = "AStoppedUpgradeWritesNoAcknowledgementTwice"
	pastTheReportStep = "TheV0110UpgradeCarriesOnPastItsReportStep"
)

// triageRenameStops is where the renames of the triage records and incidents
// are stopped.
var triageRenameStops = []renameStop{
	{after: "decision"},
	{after: "claim"},
	{after: "claim_build"},
	{after: "claim_id"},
	{after: "decision_live_unique", servers: true},
	{after: "claim_proposer_fk", servers: true},
	{after: "finding_place_idx"},
	{after: "exploited_here"},
	{after: "obligation_window_product"},
	{after: "exploited_here_id"},
	{after: "urgency_exploited_here"},
	{after: "exploited_fix_record_fk", servers: true},
	{after: "told_outside_record_idx"},
	{after: "obligation_window_product_window_fk", servers: true},
	{after: "job_set_aside_idx"},
	{after: "triage_floor"},
}

// ruleRenameStops is where the renames of the standing rules, feeds, labels
// and VEX records are stopped.
var ruleRenameStops = []renameStop{
	{after: "routing_rule"},
	{after: "routed_by"},
	{after: "routing_rule_team_fk", servers: true},
	{after: "routing_rule_order_idx"},
	{after: "advisory_source"},
	{after: "advisory_source_named_once", servers: true},
	{after: "advisory_source_due_idx"},
	{after: "finding_tag"},
	{after: "tag"},
	{after: "finding_tag_once", servers: true},
	{after: "finding_tag_named_idx"},
	{after: "vex_statement"},
	{after: "vex_statement_by_fk", servers: true},
	{after: "vex_statement_from_idx"},
	{after: "vex_issuance"},
	{after: "vex_issuance_once_per_kind", servers: true},
	{after: "vex_issuance_by_fk", servers: true},
}

// storedWordSteps is where the rewriting of stored words is stopped, in the
// order the upgrade rewrites them.
var storedWordSteps = []string{
	"decision.bulk", "notification.decision-lapsed", "outbound.decision-waiting",
	"notification.link", "notification.response-window-near", "outbound.response-window-passed",
	"admin_change.incident", "job.failed", "admin_change.assignment-rule", "job.assignment.sweep",
	"saved_filter", "application_setting",
}

// ownedStop is a rename stop and the former test it belongs to.
type ownedStop struct {
	test string
	renameStop
}

// One v0.10.0 database per engine holds the seeds of every stopped start of
// the v0.11.0 upgrade checked here, is stopped at every point, and is upgraded
// once. Building a database to v0.10.0 is most of what such a test costs, and
// a build per stop held the package past go test's limit on the servers.
//
// The stops are taken in the order the upgrade reaches them: the renames,
// then the stored words, then the changes. MySQL and MariaDB commit each
// schema statement as it runs, so there a stopped start keeps what it made
// and the next start steps over it, and a stop at a step an earlier start
// already made finds nothing to stop at. PostgreSQL and SQLite run the renames
// and stored words in the upgrade's one transaction, so each of those stops
// leaves the database as v0.10.0 left it; the changes are made in
// transactions of their own, and build on one another on every engine.
//
// On PostgreSQL and SQLite the renames and stored words are stopped at the
// first two and the last of each former test's stops (stopsTaken).
//
// Each stopped subtest makes one former test's stops, and the resumed subtest
// of the same name checks what that test pinned.
//
// Two stops have databases of their own. What a stop leaves unmade is dropped
// from a complete report step, which the shared database resumes over. The
// stand-in column of the issue kind stop carries a default v0.11.0 does not
// declare, which the upgrade steps over, so the schema it resumes to is not
// the one the others compare with v0.11.0's declaration.
func TestAV0100DatabaseResumesTheV0110UpgradeFromEveryStop(t *testing.T) {
	triage := inRenameOrder(t, slices.Clone(triageRenameStops))
	if triage[0].after != "decision" || triage[1].after != "claim" {
		t.Fatalf("the first two stops are %s and %s, and the claim table is read after decision and claim",
			triage[0].after, triage[1].after)
	}
	rules := inRenameOrder(t, slices.Clone(ruleRenameStops))
	// Both lists in the one order the upgrade renames, because on MySQL and
	// MariaDB a stop listed after a later one finds its name already renamed.
	merged := func(engine database.Engine) []ownedStop {
		var renames []ownedStop
		for test, stops := range map[string][]renameStop{renamesResume: triage, ruleRenamesResume: rules} {
			var on []renameStop
			for _, stop := range stops {
				// SQLite keeps the constraint names v0.10.0 wrote.
				if !stop.servers || engine != database.SQLite {
					on = append(on, stop)
				}
			}
			for _, stop := range stopsTaken(engine, on) {
				renames = append(renames, ownedStop{test, stop})
			}
		}
		slices.SortFunc(renames, func(a, b ownedStop) int {
			return migrations.RenameOrderV0110(a.after) - migrations.RenameOrderV0110(b.after)
		})
		return renames
	}
	all := merged(database.MySQL)
	for i := 1; i < len(all); i++ {
		if all[i].after == all[i-1].after {
			t.Fatalf("%s is stopped after twice, and the second start finds nothing to stop at", all[i].after)
		}
	}

	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		triage := seedTriageV0100(t, ctx, db)
		incidents := seedIncidentsV0100(t, ctx, db)
		rules := seedRulesV0100(t, ctx, db)
		words := seedWordsV0100(t, ctx, db)
		acknowledgedBy := acknowledgedV0100(t, ctx, db)

		// A failed stop leaves the database somewhere the later stops were
		// not written for, so it ends the test.
		stopped := func(name string, fn func(t *testing.T)) {
			t.Helper()
			if !t.Run("stopped/"+name, fn) {
				t.FailNow()
			}
		}

		// An upgrade stopped after each rename in turn, every start resuming
		// the one before it. On MySQL and MariaDB the renames already made
		// stay made and are stepped over; on PostgreSQL and SQLite each stop
		// leaves every name as it was, which the claim table shows after the
		// first two.
		for _, stop := range merged(db.Server.Engine) {
			stopped(stop.test+"/after "+stop.after, func(t *testing.T) {
				stopAt(t, stop.after, func() (bool, error) {
					return migrations.StopV0110RenamingAfter(ctx, db, stop.after)
				})
				if stop.test != renamesResume || (stop.after != "decision" && stop.after != "claim") {
					return
				}
				kept := slices.ContainsFunc(describe(t, ctx, db), func(line string) bool {
					return strings.HasPrefix(line, "column claim.")
				})
				made := stop.after == "claim" && !stopsAllAlike(db.Server.Engine)
				if kept == made {
					t.Errorf("the claim table is there after the stop at %s: %v, and the renames made by "+
						"then say %v", stop.after, kept, !made)
				}
			})
		}
		// An upgrade stopped after each step rewriting stored words in turn,
		// every start resuming the one before it.
		for _, step := range stopsTaken(db.Server.Engine, storedWordSteps) {
			stopped(storedWordsResume+"/after "+step, func(t *testing.T) {
				stopAt(t, step, func() (bool, error) {
					return migrations.StopV0110RewritingAfter(ctx, db, step)
				})
			})
		}
		// A start that stopped after writing the acknowledgements as
		// messages, and before dropping the stamp they came from: on MySQL
		// and MariaDB the messages commit at the next change to the schema.
		stopped(acknowledgedOnce, func(t *testing.T) {
			if err := migrations.StopV0110AfterAcknowledgements(ctx, db); err != nil {
				t.Fatalf("make what a stopped upgrade left: %v", err)
			}
		})
		// A start that stopped after the report step, at a later one, over
		// the acknowledgements the start before it wrote.
		stopped(pastTheReportStep, func(t *testing.T) {
			if err := migrations.RunV0110ReportStep(ctx, db); err != nil {
				t.Fatalf("make what a stopped upgrade left: %v", err)
			}
		})
		dbtest.MigrateTo(t, db, v0110)

		// Every former test that compared the schema with v0.11.0's
		// declaration compared the one this upgrade built. The upgrade starts
		// over a complete report step: MySQL and MariaDB adopt the holder
		// index for the holder's foreign key and refuse to drop it, so the
		// index is made once and never replaced.
		t.Run("resumed/TheV0110DeclarationsAreBuiltAfterEveryStop", func(t *testing.T) {
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
		})
		t.Run("resumed/"+renamesResume, func(t *testing.T) {
			triage.renamedAs(t, ctx, db)
			incidents.renamedAs(t, ctx, db)
		})
		t.Run("resumed/"+ruleRenamesResume, func(t *testing.T) {
			rules.renamedAs(t, ctx, db)
		})
		t.Run("resumed/"+storedWordsResume, func(t *testing.T) {
			wordsRenamed(t, ctx, db, words)
		})
		// The acknowledgement is one message, written once by the stopped
		// start and stepped over by the report step and the upgrade.
		t.Run("resumed/"+acknowledgedOnce, func(t *testing.T) {
			sentOnce(t, ctx, db, acknowledgedBy)
		})
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
		for _, stmt := range unmadeByAStop(db.Server.Engine) {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
		}
		dbtest.MigrateTo(t, db, v0110)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// unmadeByAStop drops what a stop after the report step can leave unmade. On
// MySQL and MariaDB the index serves a foreign key, so the key goes with it
// and comes back alone, as it stands where the table was made and the index
// was not.
func unmadeByAStop(engine database.Engine) []string {
	switch engine {
	case database.MySQL, database.MariaDB:
		return []string{
			`ALTER TABLE "report_message" DROP FOREIGN KEY "report_message_report_fk"`,
			`DROP INDEX "report_message_log_idx" ON "report_message"`,
			`ALTER TABLE "report_message" ADD CONSTRAINT "report_message_report_fk"
				FOREIGN KEY ("flaw_report_id") REFERENCES "flaw_report"("id")`,
			`ALTER TABLE "flaw_report" DROP FOREIGN KEY "flaw_report_holder_fk"`,
		}
	case database.Postgres:
		return []string{
			`DROP INDEX "report_message_log_idx"`,
			`ALTER TABLE "flaw_report" DROP CONSTRAINT "flaw_report_holder_fk"`,
		}
	}
	return []string{`DROP INDEX "report_message_log_idx"`}
}

// stopsTaken is the stops of one former test an engine takes, in order:
// every one on MySQL and MariaDB, where each stop builds on what the last
// left, and the first two and the last on PostgreSQL and SQLite, where every
// stop starts from the database as v0.10.0 left it and runs the same
// statements a step further.
func stopsTaken[S any](engine database.Engine, stops []S) []S {
	if !stopsAllAlike(engine) || len(stops) <= 3 {
		return stops
	}
	return append(slices.Clone(stops[:2]), stops[len(stops)-1])
}
