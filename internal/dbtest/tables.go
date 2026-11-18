// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Tables is every table the migrations make, in an order safe to delete from.
//
// Exported for the upgrade rehearsal, which counts the rows of every table a
// database holds. The list this returns is the one a test in this package
// holds to the migrated schema in both directions, which makes it the whole of
// them.
func Tables() []string { return slices.Clone(tables) }

// tables lists every table, in an order safe to delete from: children before
// the rows they reference.
//
// Add new tables at the top. A table missing from this list leaves rows
// behind between tests, and one in the wrong position fails on the engines
// that enforce foreign keys during a bulk delete — which is not all of them,
// so it will look engine-specific rather than like the ordering mistake it is.
var tables = []string{
	// Before flaw_report, party, person and assignment_rule, all of which it
	// points at.
	"report_assignment",
	// Before the note it belongs to.
	"report_note_revision",
	// Before flaw_report and person, both of which these point at.
	"report_note",
	"flaw_report_revision",
	"report_message",
	// Every one of these three before the one it points at, and nothing
	// outside them points in.
	"patch_commit_branch",
	"patch_commit",
	"patch_repository",
	// Before person, product, vulnerability and flaw_report, all of which it
	// points at.
	"attachment",
	// Points at nothing, so its position says nothing.
	"lease",
	// Before outbound, which it points at, and before notification, which it
	// also points at. The delivery row cascades with the notification, so the
	// order is belt as well as braces.
	"outbound_delivery",
	// Before notification, which it points at.
	"chat_delivery",
	// Before person, which it points at.
	"chat_preference",
	// Before person, which it points at.
	"notification",
	// Before person and build, both of which it points at.
	"upgrade",
	// Before person, vulnerability and product, all of which it points at.
	"disclosure_movement",
	// Before product, vulnerability, component and person, all of which it
	// points at.
	"finding_label",
	// Before person and product, both of which it points at.
	"saved_filter",
	// Before the comment it belongs to.
	"decision_comment_revision",
	"decision_comment",
	"vulnerability_reference",
	// Points at itself, which no position in this list can answer: a carried
	// agreement names the one it came from. The key is declared to null
	// rather than to block, so emptying the table needs no ordering.
	"decision_approval",
	// Before decision_occurrence and vulnerability_merge, both of which it
	// points at.
	"decision_occurrence_superseded",
	// Before decision_occurrence, which it points at.
	"source_answer",
	"decision_occurrence",
	// After the rows that point at it, and before the decision it hangs off.
	"decision_revision",
	// Before decision and build, both of which it points at.
	"decision_build",
	// Before decision, which it points at.
	"decision_stamp",
	// Before decision and product, both of which it points at.
	"source_correction",
	// Before person, which it points at, and after everything above, which
	// points at it.
	"decision",
	// Before the note it belongs to.
	"issue_note_revision",
	// Before person, product and vulnerability, all of which it points at.
	"issue_note",
	// Before the notice it belongs to.
	"told_place",
	// Before the incident, the release and the people it points at.
	"incident_fix",
	// Before the incident and the window it points at.
	"told_outside",
	// Before the window and the product it points at.
	"response_window_product",
	// Before person, which it points at, and after the rows naming it.
	"response_window",
	// Before person, product and vulnerability, all of which it points at,
	// and after the notices that point at it.
	"incident",
	// Before person, product and vulnerability, which it points at.
	"assessment",
	// Before product and vulnerability, both of which it points at.
	"issue_rating",
	// Before product and vulnerability, both of which it points at.
	"recorded_rating",
	// Before product, which it points at.
	"published_document",
	// Before upstream, which it points at.
	"upstream_document",
	// Before product and person, which it points at.
	"upstream",
	"personal_token",
	"person_identity",
	"group_admin",
	"group_role",
	"group_role_all",
	"session",
	"api_key",
	"role_grant_all",
	"role_grant",
	// Before person and product, which they point at.
	"received_vex_statement",
	// Before supplier_advisory_feed and product, both of which it points at.
	"document_upload",
	// Before product and person, both of which it points at.
	"supplier_advisory_feed",
	// Before build and person, both of which it points at.
	"published_vex",
	// Before person, which they point at.
	"admin_change",
	// Before team, person and product, all of which it points at.
	"assignment_rule",
	// Before person, product and vulnerability, all of which it points at.
	"case_collaborator",
	// Before flaw_report and report_ruling, both of which it points at.
	"report_ruled",
	// Before report_ruling, person, vulnerability and product, all of which
	// it points at.
	"flaw_report",
	// Before person, vulnerability and product, all of which it points at.
	"report_ruling",
	// Before advisory_edition, advisory and person, all of which it points
	// at. The edition is what went out, which is a fact about a moment.
	"advisory_issuance",
	// Before advisory, product, vulnerability and person, all of which it
	// points at.
	"advisory_issue",
	// Before advisory, product, vulnerability, branch or tag, variant and person,
	// all of which it points at.
	"advisory_override",
	// Before advisory_approval, product, vulnerability, branch or tag and variant,
	// all of which it points at.
	"advisory_agreed_status",
	// Before advisory_edition, advisory and person, all of which it points
	// at.
	"advisory_approval",
	// Before advisory and person, both of which it points at. The advisory
	// points back at an edition with no foreign key, so only this direction
	// has an order to keep.
	"advisory_edition",
	// After the four above, which point at it, and before person.
	"advisory",
	// Before person, which it points at.
	"outbound",
	// Before person and product, which it points at.
	"suppression_rule",
	// Before person, product and vulnerability, which they point at.
	"code_finding_flaw",
	// Before flaw_code_finding and build, which it points at.
	"flaw_code_finding_build",
	// Before person, product and vulnerability, which it points at.
	"flaw_code_finding",
	"code_finding_component",
	"code_finding_collaborator",
	// Before team and person, both of which they point at.
	"team_member",
	"team",
	"person",
	// After person and team, which point at it.
	"party",
	// Before product, which they point at.
	"repository_host",
	"repository_path",
	// Before finding and series_run, both of which they point at.
	"analysis_location",
	"analysis_result",
	"sighting",
	// Before build, which it points at.
	"series_refusal",
	// Before series_run, which they point at.
	"series_module",
	"series_document_chunk",
	"series_document",
	// Before series, scan and build, all of which it points at.
	"series_run",
	// Before product, which it points at.
	"series",
	"finding",
	"suppression",
	// After suppression and received_vex_statement, whose rows point at it with
	// no foreign key.
	"statement_text",
	// Before scan_run and vulnerability, both of which it points at, and
	// after decision_occurrence_superseded, which points at it.
	"vulnerability_merge",
	"scan_run",
	"vulnerability_alias",
	"vulnerability_weakness",
	"vulnerability_rating",
	"rule_rating",
	"rule_family",
	"vulnerability",
	"scan_document_chunk",
	"scan_document",
	"graph_edge",
	// Before graph_node, which it points at.
	"image_version",
	"graph_node",
	"component",
	"job",
	"scan_refusal",
	"scan",
	"build",
	"variant",
	"branch_or_tag",
	"product",
	"application_setting",
	"schema_change",
}

// TablesIn is every table the migrations made, sorted, read from the database
// rather than from the migration source.
//
// SQLite only: the three server engines spell this question three other ways,
// and the answer does not vary by engine — the migrations are one list of
// statements and what differs between engines is the column types. A caller
// that wants it on a server engine wants a different question.
//
// It fails rather than returning nothing, because an empty answer and a
// database nobody migrated look the same to every caller.
func TablesIn(t *testing.T, ctx context.Context, db *database.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx,
		`SELECT "name" FROM "sqlite_master" WHERE "type" = 'table' AND "name" NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var made []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		made = append(made, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(made) == 0 {
		t.Fatal("the schema declared no tables, so this checked nothing")
	}
	slices.Sort(made)
	return made
}

// Reset empties every table, leaving the schema in place.
//
// It lives here rather than in each test package so that adding a table is one
// change instead of one per package. A new table with a foreign key otherwise
// breaks the cleanup of every package that predates it, silently.
func Reset(t *testing.T, db *database.DB) {
	t.Helper()
	if err := clear(context.Background(), db); err != nil {
		t.Fatalf("reset: %v", err)
	}
}

// clear is Reset without a test to fail: the harness empties a server
// database with it before every test.
func clear(ctx context.Context, db *database.DB) error {
	return clearOf(ctx, db, tables)
}

// clearOf empties the named tables, which are in the order tables holds them.
func clearOf(ctx context.Context, db *database.DB, tables []string) error {
	// One transaction, not a statement per table. SQLite in its default mode
	// syncs the file at every commit, and a commit per table between every pair
	// of tests is a large part of what a test on SQLite costs.
	//
	// And one statement per table that holds something, rather than one per
	// table. A statement costs a round trip whether or not it changes a row —
	// 203 µs on MariaDB, 404 µs on PostgreSQL, 2,835 µs on MySQL — and a test
	// touches a few of the tables, so most of the work is
	// emptying tables that are already empty. Which ones hold anything is one
	// more statement, asked before the deletes and inside the same transaction.
	return database.InTransaction(ctx, db.DB, func(ctx context.Context, tx bun.Tx) error {
		occupied, err := occupied(ctx, db, tx, tables)
		if err != nil {
			return err
		}
		for _, table := range tables {
			if !occupied[table] {
				continue
			}
			if err := deleteRows(ctx, tx, table, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

// occupied names the tables holding at least one row, in one statement.
//
// A row per table would be one round trip per table, which is the cost this
// exists to avoid, so it is one row of one column per table: a scalar subquery
// answering 1 where the table has anything and NULL where it has not. LIMIT 1
// rather than COUNT, because the question is whether a delete has anything to
// do and a table under test can hold a quarter of a million rows. On a harness
// pool the question about every table is a statement prepared once.
func occupied(ctx context.Context, db *database.DB, tx bun.Tx, list []string) (map[string]bool, error) {
	held := make([]sql.NullInt64, len(list))
	into := make([]any, len(list))
	for i := range held {
		into[i] = &held[i]
	}
	var row *sql.Row
	var stmt *sql.Stmt
	if slices.Equal(list, tables) {
		var err error
		if stmt, err = occupancyFor(ctx, db); err != nil {
			return nil, err
		}
	}
	if stmt != nil {
		row = tx.StmtContext(ctx, stmt).QueryRowContext(ctx)
	} else {
		row = tx.QueryRowContext(ctx, occupancyQuery(list))
	}
	if err := row.Scan(into...); err != nil {
		return nil, fmt.Errorf("ask which tables hold rows: %w", err)
	}
	occupied := make(map[string]bool, len(list))
	for i, table := range list {
		occupied[table] = held[i].Valid
	}
	return occupied, nil
}

// occupancyQuery asks which of the tables hold a row.
func occupancyQuery(list []string) string {
	columns := make([]string, len(list))
	for i, table := range list {
		columns[i] = fmt.Sprintf(`(SELECT 1 FROM "%s" LIMIT 1) AS "held_%d"`, table, i)
	}
	return "SELECT " + strings.Join(columns, ", ")
}
