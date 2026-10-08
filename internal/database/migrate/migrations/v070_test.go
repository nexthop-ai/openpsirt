// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

// v070 is the migration v0.7.0 carries v0.6.0's schema across with.
const v070 = 41

// A v0.6.0 database is upgraded. Its findings gain the record lines and the
// statement answering them, its runs the snapshot, and its statements the
// product their component ships inside, holding none.
func TestAV060DatabaseUpgradesToV070(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v060)
		dbtest.MigrateTo(t, db, v070)

		var findings, runs int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "finding" WHERE "unaffected_by" IS NOT NULL`).
			Scan(ctx, &findings); err != nil {
			t.Fatalf("the finding table has no record lines: %v", err)
		}
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "scan_run" WHERE "records_version" IS NOT NULL`).
			Scan(ctx, &runs); err != nil {
			t.Fatalf("the run table has no snapshot: %v", err)
		}
		var answered, placed int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "finding" WHERE "stated_by" IS NOT NULL`).
			Scan(ctx, &answered); err != nil {
			t.Fatalf("the finding table has no statement answering it: %v", err)
		}
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "vex_statement"
			WHERE "within_purl" IS NOT NULL OR "within" IS NOT NULL OR "within_about" IS NOT NULL`).
			Scan(ctx, &placed); err != nil {
			t.Fatalf("the statement table has no product a component ships inside: %v", err)
		}
		if findings != 0 || runs != 0 || answered != 0 || placed != 0 {
			t.Errorf("upgraded, %d findings, %d runs, %d answered findings and %d statements "+
				"hold values nothing wrote", findings, runs, answered, placed)
		}
		t.Run("TheDeclarationsAreTheTablesTheMigrationsBuild", func(t *testing.T) {
			declared := migrations.StatementsV070(db.Server.Engine)
			if len(declared) != 4 {
				t.Errorf("v0.7.0 declares %d tables, want 4", len(declared))
			}
			declarationsAreBuilt(t, ctx, db, declared, madeElsewhere)
		})
	})
}

// A VEX document a v0.6.0 deployment recorded as gone out was this
// deployment's own, and is the first revision of that kind after the upgrade.
// The other kind numbers its revisions from one beside it.
func TestAnIssuanceV060RecordedIsOursAfterTheUpgrade(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v060)
		w, err := world.Declare(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		issue := func(kind string) error {
			columns := `"target_id", "ordinal", "digest", "document", "issued_by", "issued_at"`
			values := `?, 1, 'd', '{}', ?, ?`
			args := []any{w.Target.ID, w.Person.ID, time.Now().UTC()}
			if kind != "" {
				columns += `, "kind"`
				values += `, ?`
				args = append(args, kind)
			}
			_, err := db.DB.NewRaw(`INSERT INTO "vex_issuance" (`+columns+`) VALUES (`+values+`)`,
				args...).Exec(ctx)
			return err
		}
		if err := issue(""); err != nil {
			t.Fatalf("record an issuance at v0.6.0: %v", err)
		}
		dbtest.MigrateTo(t, db, v070)

		var kind string
		if err := db.DB.NewRaw(`SELECT "kind" FROM "vex_issuance"`).Scan(ctx, &kind); err != nil {
			t.Fatal(err)
		}
		if kind != "ours" {
			t.Errorf("an issuance v0.6.0 recorded reads as %q, want ours", kind)
		}
		if err := issue("with-suppliers"); err != nil {
			t.Errorf("the other kind's first revision was refused: %v", err)
		}
		if err := issue("ours"); err == nil {
			t.Error("a second first revision of the same kind was accepted")
		}
	})
}
