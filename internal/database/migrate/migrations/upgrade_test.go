// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// An upgrade that leaves a row pointing at nothing is refused on SQLite, and
// nothing it wrote is kept. Foreign keys are suspended there for the whole of
// an upgrade, so the check before the commit is the only thing between a
// rebuild that lost a parent's rows and a database with dangling references.
func TestAnUpgradeLeavingADanglingReferenceIsRefused(t *testing.T) {
	target, err := database.ParseURL("sqlite://" + t.TempDir() + "/dangling.db")
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := migrate.WithEngine(t.Context(), database.SQLite, quiet())
	for _, stmt := range []string{
		`CREATE TABLE "parent" ("id" INTEGER PRIMARY KEY)`,
		`CREATE TABLE "child" ("parent_id" INTEGER REFERENCES "parent" ("id"))`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}

	err = inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO "child" ("parent_id") VALUES (99)`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "points at no row of parent") {
		t.Errorf("an upgrade leaving a dangling reference answered %v", err)
	}
	var kept int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM "child"`).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != 0 {
		t.Errorf("%d rows the refused upgrade wrote were kept", kept)
	}

	// And foreign keys are enforced again afterwards, on the connection the
	// upgrade held.
	var enforced int
	if err := db.QueryRowContext(t.Context(), `PRAGMA foreign_keys`).Scan(&enforced); err != nil {
		t.Fatal(err)
	}
	if enforced != 1 {
		t.Error("foreign keys were left suspended after the upgrade")
	}
}

// A SQLite rebuild names every constraint as the release declares it, whatever
// the table it replaces held. A database the v0.11.0 upgrade renamed keeps the
// constraint names from before the renames, while one the baseline made has
// the declared names, so a later rebuild leaves both the same.
func TestASQLiteRebuildTakesTheDeclaredConstraintNames(t *testing.T) {
	target, err := database.ParseURL("sqlite://" + t.TempDir() + "/renamed.db")
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := migrate.WithEngine(t.Context(), database.SQLite, quiet())
	for _, stmt := range []string{
		`CREATE TABLE "decision" ("id" INTEGER PRIMARY KEY, "build" INTEGER NOT NULL,
			CONSTRAINT "claim_build_once" UNIQUE ("build"))`,
		`INSERT INTO "decision" ("id", "build") VALUES (1, 7)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}

	declaration := []string{`CREATE TABLE "decision" (
		"id" INTEGER PRIMARY KEY,
		"build" INTEGER NOT NULL,
		"reviewed" INTEGER NOT NULL,
		CONSTRAINT "decision_build_once" UNIQUE ("build")
	)`}
	err = inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		return u.change(declaration, change{table: "decision",
			add: []added{{column: "reviewed", fill: "0"}}})
	})
	if err != nil {
		t.Fatal(err)
	}

	var made string
	if err := db.QueryRowContext(t.Context(),
		`SELECT "sql" FROM "sqlite_master" WHERE "type" = 'table' AND "name" = 'decision'`).Scan(&made); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(made, `"decision_build_once"`) || strings.Contains(made, `"claim_build_once"`) {
		t.Errorf("the rebuilt table is declared as %s", made)
	}
	var kept int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM "decision" WHERE "build" = 7`).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != 1 {
		t.Errorf("the rebuild kept %d of the table's one row", kept)
	}
}
