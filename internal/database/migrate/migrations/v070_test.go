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
			WHERE "within_purl" IS NOT NULL OR "within" IS NOT NULL OR "within_about" IS NOT NULL
				OR "placement" IS NOT NULL`).
			Scan(ctx, &placed); err != nil {
			t.Fatalf("the statement table has no product a component ships inside: %v", err)
		}
		var claimed, inside int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "finding" WHERE "claimed_by" IS NOT NULL`).
			Scan(ctx, &claimed); err != nil {
			t.Fatalf("the finding table has no build claim covering it: %v", err)
		}
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "suppression"
			WHERE "within_purl" IS NOT NULL OR "within_name" IS NOT NULL
				OR "within_version" IS NOT NULL OR "stated_by" IS NOT NULL`).
			Scan(ctx, &inside); err != nil {
			t.Fatalf("the claim table has no product a subject ships inside: %v", err)
		}
		if findings != 0 || runs != 0 || answered != 0 || placed != 0 || claimed != 0 || inside != 0 {
			t.Errorf("upgraded, %d findings, %d runs, %d answered findings, %d statements, "+
				"%d claimed findings and %d claims hold values nothing wrote",
				findings, runs, answered, placed, claimed, inside)
		}
		t.Run("TheDeclarationsAreTheTablesTheMigrationsBuild", func(t *testing.T) {
			declared := migrations.StatementsV070(db.Server.Engine)
			if len(declared) != 5 {
				t.Errorf("v0.7.0 declares %d tables, want 5", len(declared))
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

// A supplier read from its directory before the upgrade is read again from its
// window after it, so what it published is read with the product each
// statement places.
func TestASupplierIsReadAgainAfterTheUpgrade(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v060)
		w, err := world.Declare(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		if _, err := db.DB.NewRaw(`INSERT INTO "advisory_source" ("product_id", "name",
			"display_name", "url", "caught_up_to", "caught_up_mark", "created_by", "created_at")
			VALUES (?, 'acme', 'Acme', 'https://acme.example/provider-metadata.json', ?, 'mark', ?, ?)`,
			w.Product.ID, now, w.Person.ID, now).Exec(ctx); err != nil {
			t.Fatalf("configure a supplier at v0.6.0: %v", err)
		}
		dbtest.MigrateTo(t, db, v070)

		var held int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "advisory_source"
			WHERE "caught_up_to" IS NOT NULL OR "caught_up_mark" IS NOT NULL`).Scan(ctx, &held); err != nil {
			t.Fatal(err)
		}
		if held != 0 {
			t.Errorf("%d suppliers kept how far they had read", held)
		}
	})
}
