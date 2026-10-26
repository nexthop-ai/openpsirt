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
// made on and a commitment citing it.
type triageV0100 struct{ claim, decision, revision int64 }

func seedTriageV0100(t *testing.T, ctx context.Context, db *database.DB) triageV0100 {
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
	exec(`INSERT INTO "claim_build" ("claim_id", "target_id") VALUES (?, ?)`, out.claim, declared.Target.ID)
	exec(`INSERT INTO "upgrade" ("target_id", "fold_key", "from_version", "to_version", "claim_id",
		"declared_by", "declared_at") VALUES (?, ?, ?, ?, ?, ?, ?)`,
		declared.Target.ID, "fold-libfoo", "1.0", "1.1", out.claim, person, at)
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
}

// A v0.10.0 database holding a claim and everything beside it is upgraded,
// and every row reads back under v0.11.0's names in the shape the release
// declares.
func TestAV0100DatabaseTakesTheV0110TriageNames(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		seeded := seedTriageV0100(t, ctx, db)
		dbtest.MigrateTo(t, db, v0110)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
		seeded.renamedAs(t, ctx, db)
		leaveAtLatest(t, ctx, db)
	})
}

// An upgrade stopped after any one rename is started again, and leaves what
// one that did not stop leaves. On MySQL and MariaDB the renames already made
// stay made and are stepped over; on PostgreSQL and SQLite the stop leaves
// every name as it was.
func TestAnUpgradeStoppedPartWayThroughItsRenamesResumes(t *testing.T) {
	for _, stop := range []struct {
		after string
		// servers is a constraint SQLite does not rename.
		servers bool
	}{
		{after: "decision"},
		{after: "claim"},
		{after: "claim_build"},
		{after: "claim_id"},
		{after: "decision_live_unique", servers: true},
		{after: "claim_proposer_fk", servers: true},
		{after: "finding_place_idx"},
	} {
		t.Run(stop.after, func(t *testing.T) {
			dbtest.Each(t, func(t *testing.T, db *database.DB) {
				if stop.servers && db.Server.Engine == database.SQLite {
					t.Skip("SQLite keeps the constraint names v0.10.0 wrote")
				}
				ctx := t.Context()
				dbtest.Empty(t, db)
				dbtest.MigrateTo(t, db, v0100)
				seeded := seedTriageV0100(t, ctx, db)
				stopped, err := migrations.StopV0110RenamingAfter(ctx, db, stop.after)
				if err != nil {
					t.Fatal(err)
				}
				if !stopped {
					t.Fatalf("nothing renames %s here, so this stopped nothing", stop.after)
				}
				kept := slices.ContainsFunc(describe(t, ctx, db), func(line string) bool {
					return strings.HasPrefix(line, "column claim.")
				})
				switch db.Server.Engine {
				case database.MySQL, database.MariaDB:
					if kept != (stop.after == "decision") {
						t.Errorf("the claim table is there after the stop: %v, and the renames made by then "+
							"say %v", kept, stop.after == "decision")
					}
				default:
					if !kept {
						t.Error("the stop left the claim table renamed, which a rolled-back upgrade does not")
					}
				}
				dbtest.MigrateTo(t, db, v0110)
				declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
				seeded.renamedAs(t, ctx, db)
				leaveAtLatest(t, ctx, db)
			})
		})
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
