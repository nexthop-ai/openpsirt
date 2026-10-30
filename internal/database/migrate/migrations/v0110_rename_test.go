// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

// triageV0100 is one claim in a v0.10.0 database with a row at a place, a
// revision, an approval, a comment and its earlier wording, a build it was
// made on and a commitment citing it, and a product stating the least severity
// it triages.
type triageV0100 struct{ claim, decision, revision int64 }

func seedTriageV0100(t *testing.T, ctx context.Context, db *database.DB) triageV0100 {
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
	person, product := declared.Person.ID, declared.Product.ID
	exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
		VALUES (?, ?, ?, ?, ?)`, "cve-2026-4500", "cve-2026-4500", false, at, 0)
	issue := id(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, "cve-2026-4500")
	exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, issue)

	exec(`INSERT INTO "claim" ("kind", "proposed_by", "proposed_at", "outcome") VALUES (?, ?, ?, ?)`,
		"finding", person, at, "not-applicable")
	out := triageV0100{claim: id(`SELECT MAX("id") FROM "claim"`)}
	exec(`INSERT INTO "decision" ("claim_id", "product_id", "vulnerability_id", "place_identity", "visibility",
		"needs_approval", "state", "proposed_by", "proposed_at", "live_key")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		out.claim, product, issue, "place-libfoo", "public", true, "approved", person, at, "key-libfoo")
	out.decision = id(`SELECT MAX("id") FROM "decision"`)
	exec(`INSERT INTO "claim_revision" ("claim_id", "ordinal", "body", "written_by", "written_at")
		VALUES (?, ?, ?, ?, ?)`, out.claim, 1, "Not reachable here.", person, at)
	out.revision = id(`SELECT MAX("id") FROM "claim_revision"`)
	exec(`INSERT INTO "claim_approval" ("claim_id", "revision_id", "approved_by", "approved_at")
		VALUES (?, ?, ?, ?)`, out.claim, out.revision, person, at)
	exec(`INSERT INTO "claim_comment" ("claim_id", "body", "written_by", "written_at")
		VALUES (?, ?, ?, ?)`, out.claim, "Checked twice.", person, at)
	comment := id(`SELECT MAX("id") FROM "claim_comment"`)
	exec(`INSERT INTO "claim_comment_revision" ("comment_id", "ordinal", "body", "replaced_at")
		VALUES (?, ?, ?, ?)`, comment, 1, "Checked once.", at)
	exec(`INSERT INTO "claim_build" ("claim_id", "target_id") VALUES (?, ?)`, out.claim, declared.Build.ID)
	exec(`INSERT INTO "upgrade" ("target_id", "fold_key", "from_version", "to_version", "claim_id",
		"declared_by", "declared_at") VALUES (?, ?, ?, ?, ?, ?, ?)`,
		declared.Build.ID, "fold-libfoo", "1.0", "1.1", out.claim, person, at)
	exec(`UPDATE "product" SET "triage_floor" = ? WHERE "id" = ?`, "high", product)
	return out
}

// renamedAs asserts every row the seed wrote is read back under v0.11.0's
// names, each pointing where it pointed before.
func (w triageV0100) renamedAs(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	for _, c := range []struct{ what, query string }{
		{"the decision", `SELECT COUNT(*) FROM "decision" WHERE "id" = ?`},
		{"its occurrence", `SELECT COUNT(*) FROM "decision_occurrence"
			WHERE "decision_id" = ? AND "occurrence_identity" = 'place-libfoo'`},
		{"its revision", `SELECT COUNT(*) FROM "decision_revision" WHERE "decision_id" = ?`},
		{"its approval", `SELECT COUNT(*) FROM "decision_approval" WHERE "decision_id" = ?`},
		{"its comment", `SELECT COUNT(*) FROM "decision_comment" WHERE "decision_id" = ?`},
		{"its comment's earlier wording", `SELECT COUNT(*) FROM "decision_comment_revision" AS "r"
			JOIN "decision_comment" AS "c" ON "c"."id" = "r"."comment_id" WHERE "c"."decision_id" = ?`},
		{"the build it was made on", `SELECT COUNT(*) FROM "decision_build" WHERE "decision_id" = ?`},
		{"the commitment citing it", `SELECT COUNT(*) FROM "upgrade" WHERE "decision_id" = ?`},
	} {
		var n int
		if err := db.DB.NewRaw(c.query, w.claim).Scan(ctx, &n); err != nil {
			t.Fatalf("read %s: %v", c.what, err)
		}
		if n != 1 {
			t.Errorf("%s reads %d rows after the upgrade, want 1", c.what, n)
		}
	}
	var occurrence int64
	if err := db.DB.NewRaw(`SELECT "id" FROM "decision_occurrence" WHERE "decision_id" = ?`,
		w.claim).Scan(ctx, &occurrence); err != nil {
		t.Fatal(err)
	}
	if occurrence != w.decision {
		t.Errorf("the occurrence is row %d after the upgrade, want the row %d it was", occurrence, w.decision)
	}
	var stated int
	if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "product" WHERE "minimum_severity" = 'high'`).
		Scan(ctx, &stated); err != nil {
		t.Fatal(err)
	}
	if stated != 1 {
		t.Errorf("%d products state a minimum severity of high after the upgrade, want 1", stated)
	}
}

// incidentsV0100 is, in a v0.10.0 database, a record that the product was
// attacked, a release named as carrying its fix, a notice outside about it, a
// window counted from another and limited to the product, and a finding the
// record ranks first.
type incidentsV0100 struct{ incident, fix, told, window, finding int64 }

// seedIncidentsV0100 writes the rows beside the fixture's product.
func seedIncidentsV0100(t *testing.T, ctx context.Context, db *database.DB) incidentsV0100 {
	t.Helper()
	worldBeforeV0110(t, ctx, db)
	at := time.Date(2026, 10, 20, 3, 0, 0, 0, time.UTC)
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
	person := id(`SELECT "id" FROM "person" WHERE "identity" = ?`, world.PersonIdentity)
	product := id(`SELECT "id" FROM "product" WHERE "name" = ?`, world.ProductName)
	tag := id(`SELECT "id" FROM "stream" WHERE "product_id" = ? AND "name" = ?`, product, world.TagName)
	target := id(`SELECT MIN("t"."id") FROM "target" AS "t" JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"
		WHERE "s"."product_id" = ? AND "s"."name" = ?`, product, world.BranchName)
	exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
		VALUES (?, ?, ?, ?, ?)`, "cve-2026-4600", "cve-2026-4600", true, at, 0)
	issue := id(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, "cve-2026-4600")
	exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, issue)
	exec(`INSERT INTO "exploited_here" ("vulnerability_id", "product_id", "known_at", "grounds", "recorded_by",
		"recorded_at", "live_vulnerability_id") VALUES (?, ?, ?, ?, ?, ?, ?)`,
		issue, product, at, "A customer's logs.", person, at, issue)
	var out incidentsV0100
	out.incident = id(`SELECT MAX("id") FROM "exploited_here"`)
	exec(`INSERT INTO "exploited_fix" ("exploited_here_id", "stream_id", "named_by", "named_at", "live_stream_id")
		VALUES (?, ?, ?, ?, ?)`, out.incident, tag, person, at, tag)
	out.fix = id(`SELECT MAX("id") FROM "exploited_fix"`)
	exec(`INSERT INTO "obligation_window" ("name", "length_hours", "declared_by", "declared_at", "live_name",
		"from_fix") VALUES (?, ?, ?, ?, ?, ?)`, "Early warning", 24, person, at, "early warning", false)
	first := id(`SELECT MAX("id") FROM "obligation_window"`)
	exec(`INSERT INTO "obligation_window" ("name", "length_hours", "lead_hours", "declared_by", "declared_at",
		"live_name", "from_window_id", "from_fix") VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"Full report", 72, 12, person, at, "full report", first, false)
	out.window = id(`SELECT MAX("id") FROM "obligation_window"`)
	exec(`INSERT INTO "obligation_window_product" ("window_id", "product_id") VALUES (?, ?)`, out.window, product)
	exec(`INSERT INTO "told_outside" ("exploited_here_id", "window_id", "recipient", "told_at", "said",
		"recorded_by", "recorded_at") VALUES (?, ?, ?, ?, ?, ?, ?)`,
		out.incident, first, "The national response team", at, "It was attacked.", person, at)
	out.told = id(`SELECT MAX("id") FROM "told_outside"`)
	exec(`INSERT INTO "component" ("identity", "name", "version", "name_folded", "fold_key", "first_seen_at")
		VALUES (?, ?, ?, ?, ?, ?)`, "libbar", "libbar", "2.0", "libbar", "libbar", at)
	component := id(`SELECT "id" FROM "component" WHERE "identity" = ?`, "libbar")
	exec(`INSERT INTO "finding" ("target_id", "kind", "visibility", "vulnerability_id", "component_id",
		"place_identity", "urgency", "urgency_exploited", "urgency_exploited_here", "urgency_shipped", "opened_at")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		target, "vulnerability", "public", issue, component, "place-libbar", 1, true, true, true, at)
	out.finding = id(`SELECT MAX("id") FROM "finding"`)
	return out
}

// renamedAs asserts every row the seed wrote is read back under v0.11.0's
// names, each pointing where it pointed before.
func (w incidentsV0100) renamedAs(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	for _, c := range []struct {
		what, query string
		args        []any
	}{
		{"the incident", `SELECT COUNT(*) FROM "incident" WHERE "id" = ? AND "live_vulnerability_id" IS NOT NULL`,
			[]any{w.incident}},
		{"the release carrying its fix", `SELECT COUNT(*) FROM "incident_fix" WHERE "id" = ? AND "incident_id" = ?`,
			[]any{w.fix, w.incident}},
		{"the notice outside", `SELECT COUNT(*) FROM "told_outside" AS "t"
			JOIN "response_window" AS "w" ON "w"."id" = "t"."window_id"
			WHERE "t"."id" = ? AND "t"."incident_id" = ? AND "w"."name" = 'Early warning'`,
			[]any{w.told, w.incident}},
		{"the window counted from another", `SELECT COUNT(*) FROM "response_window" AS "w"
			JOIN "response_window" AS "f" ON "f"."id" = "w"."from_window_id"
			WHERE "w"."id" = ? AND "w"."lead_hours" = 12`, []any{w.window}},
		{"the product the window is limited to", `SELECT COUNT(*) FROM "response_window_product"
			WHERE "window_id" = ?`, []any{w.window}},
		{"the finding the incident ranks first", `SELECT COUNT(*) FROM "finding"
			WHERE "id" = ? AND "urgency_incident" = ?`, []any{w.finding, true}},
	} {
		var n int
		if err := db.DB.NewRaw(c.query, c.args...).Scan(ctx, &n); err != nil {
			t.Fatalf("read %s: %v", c.what, err)
		}
		if n != 1 {
			t.Errorf("%s reads %d rows after the upgrade, want 1", c.what, n)
		}
	}
}

// numberedAfter asserts a window declared after the upgrade is numbered after
// every window the database held. It writes the window.
func (w incidentsV0100) numberedAfter(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	var person int64
	if err := db.DB.NewRaw(`SELECT "recorded_by" FROM "incident" WHERE "id" = ?`,
		w.incident).Scan(ctx, &person); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.NewRaw(`INSERT INTO "response_window" ("name", "length_hours", "declared_by",
		"declared_at", "live_name", "from_fix") VALUES (?, ?, ?, ?, ?, ?)`,
		"Final report", 720, person, time.Now().UTC(), "final report", false).Exec(ctx); err != nil {
		t.Fatalf("declare a window after the upgrade: %v", err)
	}
	var next int64
	if err := db.DB.NewRaw(`SELECT MAX("id") FROM "response_window"`).Scan(ctx, &next); err != nil {
		t.Fatal(err)
	}
	if next <= w.window {
		t.Errorf("a window declared after the upgrade is row %d, at or before row %d it held", next,
			w.window)
	}
}

// An upgrade stopped after each rename in turn, every start resuming the one
// before it, is started again, and leaves what one that did not stop leaves.
// On MySQL and MariaDB the renames already made stay made and are stepped
// over; on PostgreSQL and SQLite each stop leaves every name as it was.
//
// One database per engine runs every stop, rather than one per stop, because
// migrating a fresh database to v0.10.0 is most of each run's time, and a run
// per stop held the package past go test's limit on the servers. The stops
// are taken in the order the upgrade renames, because on MySQL and MariaDB a
// stop at a name an earlier start already renamed finds nothing to stop at.
func TestAnUpgradeStoppedPartWayThroughItsRenamesResumes(t *testing.T) {
	stops := inRenameOrder(t, []renameStop{
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
	})
	if stops[0].after != "decision" || stops[1].after != "claim" {
		t.Fatalf("the first two stops are %s and %s, and the claim table is read after decision and claim",
			stops[0].after, stops[1].after)
	}
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		seeded := seedTriageV0100(t, ctx, db)
		incidents := seedIncidentsV0100(t, ctx, db)
		for i, stop := range stops {
			if stop.servers && db.Server.Engine == database.SQLite {
				continue // SQLite keeps the constraint names v0.10.0 wrote.
			}
			stopAt(t, stop.after, func() (bool, error) {
				return migrations.StopV0110RenamingAfter(ctx, db, stop.after)
			})
			if i > 1 {
				continue
			}
			kept := slices.ContainsFunc(describe(t, ctx, db), func(line string) bool {
				return strings.HasPrefix(line, "column claim.")
			})
			made := stop.after == "claim" && !stopsAllAlike(db.Server.Engine)
			if kept == made {
				t.Errorf("the claim table is there after the stop at %s: %v, and the renames made by "+
					"then say %v", stop.after, kept, !made)
			}
		}
		dbtest.MigrateTo(t, db, v0110)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
		seeded.renamedAs(t, ctx, db)
		incidents.renamedAs(t, ctx, db)
		leaveAtLatest(t, ctx, db)
	})
}

// renameStop is a rename an upgrade is stopped after.
type renameStop struct {
	after string
	// servers is a constraint SQLite does not rename.
	servers bool
}

// inRenameOrder sorts stops into the order the upgrade runs its renames.
func inRenameOrder(t *testing.T, stops []renameStop) []renameStop {
	t.Helper()
	for _, stop := range stops {
		if migrations.RenameOrderV0110(stop.after) < 0 {
			t.Fatalf("nothing renames %s, so a stop there stops nothing", stop.after)
		}
	}
	slices.SortStableFunc(stops, func(a, b renameStop) int {
		return migrations.RenameOrderV0110(a.after) - migrations.RenameOrderV0110(b.after)
	})
	return stops
}

// stopsAllAlike is whether every stop leaves the database as it was:
// PostgreSQL and SQLite run the renames in the upgrade's one transaction.
func stopsAllAlike(engine database.Engine) bool {
	return engine == database.Postgres || engine == database.SQLite
}

// stopAt runs a start of the upgrade that stops after the named step, and
// fails the test where the start did not stop there.
func stopAt(t *testing.T, after string, start func() (bool, error)) {
	t.Helper()
	stopped, err := start()
	if err != nil {
		t.Fatalf("the start stopping after %s: %v", after, err)
	}
	if !stopped {
		t.Fatalf("nothing ran %s, so the stop there stopped nothing: a stop listed out of the "+
			"upgrade's order finds it already made on MySQL and MariaDB", after)
	}
}

// A rename whose table another session holds waits its bound, says what holds
// the table, and runs once the session lets go. SQLite holds the database for
// the whole upgrade, so nothing waits there.
func TestARenameWaitsForWhatHoldsItsTableAndSaysWhat(t *testing.T) {
	dbtest.Servers(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		seedTriageV0100(t, ctx, db)

		holder, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = holder.Rollback() }()
		var n int
		if err := holder.NewRaw(`SELECT COUNT(*) FROM "claim"`).Scan(ctx, &n); err != nil {
			t.Fatal(err)
		}

		var logged lockedBuffer
		logger := slog.New(slog.NewTextHandler(&logged, nil))
		done := make(chan error, 1)
		go func() { done <- migrate.UpTo(context.WithoutCancel(ctx), db, logger, v0110) }()

		deadline := time.Now().Add(30 * time.Second)
		for !strings.Contains(logged.String(), "a rename is waiting for a table something else holds") {
			if time.Now().After(deadline) {
				t.Fatalf("no wait was logged while the table was held:\n%s", logged.String())
			}
			select {
			case err := <-done:
				t.Fatalf("the upgrade finished while the table was held: %v", err)
			case <-time.After(200 * time.Millisecond):
			}
		}
		if err := holder.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatalf("the upgrade failed once the table was let go: %v", err)
		}
		said := logged.String()
		if strings.Contains(said, "held_by=\"[nothing this session can see]\"") ||
			strings.Contains(said, "could not be read") {
			t.Errorf("the wait was logged without what holds the table:\n%s", said)
		}
		leaveAtLatest(t, ctx, db)
	})
}

// lockedBuffer is a log written by one goroutine and read by another.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
