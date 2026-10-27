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

// savedV0100 is a kept filter's address as v0.10.0 wrote it, naming every
// word v0.11.0 renames beside words it keeps, and savedV0110 the same address
// in v0.11.0's words.
const (
	savedV0100 = "claim=7&claim_state=waiting&claim_state=lapsed&sort=places&asc=true&fix_state=none"
	savedV0110 = "decision=7&decision_state=waiting&decision_state=lapsed&sort=occurrences&asc=true&fix_state=none"
)

// seedWordsV0100 writes, in a v0.10.0 database, a row holding each stored
// word v0.11.0 renames: a bulk claim, a notification and a destination of
// each renamed kind, a notification linking a decision's row and one linking
// a claim, a job that ran out of attempts beside one that finished, a kept
// filter naming the renamed words, the bulk action limit and the minimum
// severity under their v0.10.0 names, and a change on the trail of the
// renamed kind beside one of a kind kept.
func seedWordsV0100(t *testing.T, ctx context.Context, db *database.DB) {
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
	person := declared.Person.ID
	exec(`INSERT INTO "claim" ("kind", "proposed_by", "proposed_at", "outcome") VALUES (?, ?, ?, ?)`,
		"together", person, at, "not-applicable")
	exec(`INSERT INTO "claim" ("kind", "proposed_by", "proposed_at", "outcome") VALUES (?, ?, ?, ?)`,
		"finding", person, at, "not-applicable")
	for i, kind := range []string{"claim-waiting", "claim-lapsed", "obligation-open", "obligation-near",
		"obligation-passed", "assigned"} {
		exec(`INSERT INTO "notification" ("person_id", "kind", "lifetime", "about", "body", "link",
			"private", "together", "attempts", "created_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			person, kind, "event", "about-"+kind, "Something happened.", "/", false, "", 0, at)
		exec(`INSERT INTO "outbound" ("name", "display_name", "kind", "url", "secret", "created_by",
			"created_at", "platform") VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			"hook", "hook", kind, "https://example.com/"+string(rune('a'+i)), "", person, at, "webhook")
	}
	for _, link := range []string{"/decisions/34", "/claims/7"} {
		exec(`INSERT INTO "notification" ("person_id", "kind", "lifetime", "about", "body", "link",
			"private", "together", "attempts", "created_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			person, "sent-back", "event", "about-"+link, "Sent back.", link, false, "", 0, at)
	}
	for _, state := range []string{"dead", "done"} {
		exec(`INSERT INTO "job" ("kind", "reference", "state", "attempts", "max_attempts", "run_after",
			"created_at", "updated_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			"scan", "target:"+state, state, 5, 5, at, at, at)
	}
	exec(`INSERT INTO "saved_filter" ("person_id", "name", "query", "created_at") VALUES (?, ?, ?, ?)`,
		person, "waiting", savedV0100, at)
	exec(`INSERT INTO "saved_filter" ("person_id", "name", "query", "created_at") VALUES (?, ?, ?, ?)`,
		person, "kept", "outcome=not-applicable&exclude=placeholder-claims", at)
	exec(`INSERT INTO "application_setting" ("name", "value", "updated_at") VALUES (?, ?, ?)`,
		"triage.together-cap", "250", at)
	for _, kind := range []string{"exploited-here", "setting"} {
		exec(`INSERT INTO "admin_change" ("at", "by", "actor", "kind", "about", "was", "became")
			VALUES (?, ?, ?, ?, ?, ?, ?)`, at, person, "person", kind, "Obligation window Early warning", nil, "24")
	}
	exec(`INSERT INTO "application_setting" ("name", "value", "updated_at") VALUES (?, ?, ?)`,
		"triage.floor", "medium", at)
}

// wordsRenamed asserts every stored word the seed wrote reads in v0.11.0's
// spelling, and every word v0.11.0 keeps reads as it was written.
func wordsRenamed(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	for _, c := range []struct {
		what, query string
		want        int
	}{
		{"a bulk decision", `SELECT COUNT(*) FROM "decision" WHERE "kind" = 'bulk'`, 1},
		{"a decision of one finding", `SELECT COUNT(*) FROM "decision" WHERE "kind" = 'finding'`, 1},
		{"a decision of the v0.10.0 kind", `SELECT COUNT(*) FROM "decision" WHERE "kind" = 'together'`, 0},
		{"a notification of a decision waiting",
			`SELECT COUNT(*) FROM "notification" WHERE "kind" = 'decision-waiting'`, 1},
		{"a notification of a decision lapsed",
			`SELECT COUNT(*) FROM "notification" WHERE "kind" = 'decision-lapsed'`, 1},
		{"a notification of a response window running",
			`SELECT COUNT(*) FROM "notification" WHERE "kind" = 'response-window-open'`, 1},
		{"a notification of a response window ending",
			`SELECT COUNT(*) FROM "notification" WHERE "kind" = 'response-window-near'`, 1},
		{"a notification of a response window passed",
			`SELECT COUNT(*) FROM "notification" WHERE "kind" = 'response-window-passed'`, 1},
		{"a notification of a kind kept", `SELECT COUNT(*) FROM "notification" WHERE "kind" = 'assigned'`, 1},
		{"a notification of a v0.10.0 kind", `SELECT COUNT(*) FROM "notification" WHERE "kind" IN
			('claim-waiting', 'claim-lapsed', 'obligation-open', 'obligation-near', 'obligation-passed')`, 0},
		{"a destination of a decision waiting",
			`SELECT COUNT(*) FROM "outbound" WHERE "kind" = 'decision-waiting'`, 1},
		{"a destination of a decision lapsed",
			`SELECT COUNT(*) FROM "outbound" WHERE "kind" = 'decision-lapsed'`, 1},
		{"a link to a decision's row at its new address",
			`SELECT COUNT(*) FROM "notification" WHERE "link" = '/decision-occurrences/34'`, 1},
		{"a link to a decision's row at its v0.10.0 address",
			`SELECT COUNT(*) FROM "notification" WHERE "link" = '/decisions/34'`, 0},
		{"a link to a decision, left for the interface to forward",
			`SELECT COUNT(*) FROM "notification" WHERE "link" = '/claims/7'`, 1},
		{"a destination of a response window running",
			`SELECT COUNT(*) FROM "outbound" WHERE "kind" = 'response-window-open'`, 1},
		{"a destination of a response window ending",
			`SELECT COUNT(*) FROM "outbound" WHERE "kind" = 'response-window-near'`, 1},
		{"a destination of a response window passed",
			`SELECT COUNT(*) FROM "outbound" WHERE "kind" = 'response-window-passed'`, 1},
		{"a destination of a v0.10.0 kind", `SELECT COUNT(*) FROM "outbound" WHERE "kind" IN
			('claim-waiting', 'claim-lapsed', 'obligation-open', 'obligation-near', 'obligation-passed')`, 0},
		{"a change to an incident", `SELECT COUNT(*) FROM "admin_change" WHERE "kind" = 'incident'`, 1},
		{"a change of a kind kept", `SELECT COUNT(*) FROM "admin_change" WHERE "kind" = 'setting'`, 1},
		{"a change of the v0.10.0 kind", `SELECT COUNT(*) FROM "admin_change" WHERE "kind" = 'exploited-here'`, 0},
		{"what a change was about, as written", `SELECT COUNT(*) FROM "admin_change"
			WHERE "about" = 'Obligation window Early warning'`, 2},
		{"a job that ran out of attempts", `SELECT COUNT(*) FROM "job"
			WHERE "state" = 'failed' AND "reference" = 'target:dead'`, 1},
		{"a job that finished", `SELECT COUNT(*) FROM "job" WHERE "state" = 'done'`, 1},
		{"a job of the v0.10.0 state", `SELECT COUNT(*) FROM "job" WHERE "state" = 'dead'`, 0},
		{"the limit under its new name", `SELECT COUNT(*) FROM "application_setting"
			WHERE "name" = 'triage.bulk-decision-cap' AND "value" = '250'`, 1},
		{"the limit under its v0.10.0 name",
			`SELECT COUNT(*) FROM "application_setting" WHERE "name" = 'triage.together-cap'`, 0},
		{"the minimum severity under its new name", `SELECT COUNT(*) FROM "application_setting"
			WHERE "name" = 'triage.minimum-severity' AND "value" = 'medium'`, 1},
		{"the minimum severity under its v0.10.0 name",
			`SELECT COUNT(*) FROM "application_setting" WHERE "name" = 'triage.floor'`, 0},
	} {
		var n int
		if err := db.DB.NewRaw(c.query).Scan(ctx, &n); err != nil {
			t.Fatalf("read %s: %v", c.what, err)
		}
		if n != c.want {
			t.Errorf("%s: %d rows after the upgrade, want %d", c.what, n, c.want)
		}
	}
	for name, want := range map[string]string{
		"waiting": savedV0110,
		"kept":    "outcome=not-applicable&exclude=placeholder-claims",
	} {
		var query string
		if err := db.DB.NewRaw(`SELECT "query" FROM "saved_filter" WHERE "name" = ?`, name).
			Scan(ctx, &query); err != nil {
			t.Fatal(err)
		}
		if query != want {
			t.Errorf("the kept filter %q opens %q after the upgrade, want %q", name, query, want)
		}
	}
}

// A v0.10.0 database holding every stored word v0.11.0 renames is upgraded,
// and each reads in v0.11.0's spelling.
func TestAV0100DatabaseTakesTheV0110StoredWords(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		seedWordsV0100(t, ctx, db)
		dbtest.MigrateTo(t, db, v0110)
		wordsRenamed(t, ctx, db)
		leaveAtLatest(t, ctx, db)
	})
}

// An upgrade stopped after any one step rewriting stored words is started
// again, and leaves what one that did not stop leaves.
func TestAnUpgradeStoppedPartWayThroughItsStoredWordsResumes(t *testing.T) {
	for _, step := range []string{
		"decision.bulk", "notification.decision-lapsed", "outbound.decision-waiting",
		"notification.link", "notification.response-window-near", "outbound.response-window-passed",
		"admin_change.incident", "job.failed", "saved_filter", "application_setting",
	} {
		t.Run(step, func(t *testing.T) {
			dbtest.Each(t, func(t *testing.T, db *database.DB) {
				ctx := t.Context()
				dbtest.Empty(t, db)
				dbtest.MigrateTo(t, db, v0100)
				seedWordsV0100(t, ctx, db)
				stopped, err := migrations.StopV0110RewritingAfter(ctx, db, step)
				if err != nil {
					t.Fatal(err)
				}
				if !stopped {
					t.Fatalf("no step is named %s, so this stopped nothing", step)
				}
				dbtest.MigrateTo(t, db, v0110)
				wordsRenamed(t, ctx, db)
				leaveAtLatest(t, ctx, db)
			})
		})
	}
}

// A kept filter's address takes v0.11.0's words for a word of the address and
// for an order, and keeps every other part byte for byte: a value spelled like
// a renamed word, an order under another word, and a part with no value.
func TestAKeptFilterRenamesOnlyTheWordsOfItsAddress(t *testing.T) {
	for _, c := range []struct{ from, to string }{
		{savedV0100, savedV0110},
		{"", ""},
		{"exclude=claim&outcome=places", "exclude=claim&outcome=places"},
		{"claim_state&sort=urgency", "decision_state&sort=urgency"},
		{"sort=places", "sort=occurrences"},
		{"under=claim%5Fstate", "under=claim%5Fstate"},
	} {
		if got := migrations.SavedQueryV0110(c.from); got != c.to {
			t.Errorf("%q became %q, want %q", c.from, got, c.to)
		}
	}
}
