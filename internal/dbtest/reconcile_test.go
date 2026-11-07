// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// A seeded database an earlier test changed in every way reconcile undoes
// row by row reads, once reconciled, exactly as the seed left it: a kept row
// changed, a kept row deleted, a kept row a foreign key's action deleted with
// its parent, a kept row moved onto a row the test added, rows added beside
// kept ones and referencing each other in their own table, rows in a table
// the seed left empty, and a table without an identifier changed and added
// to.
func TestASeededDatabaseAnEarlierTestChangedReadsAsTheSeedLeftIt(t *testing.T) {
	Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		at := time.Date(2026, 10, 30, 12, 34, 56, 123456000, time.UTC)
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := db.ExecContext(ctx, query, args...); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
		}
		id := func(query string, args ...any) int64 {
			t.Helper()
			var out int64
			if err := db.NewRaw(query, args...).Scan(ctx, &out); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
			return out
		}

		exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "kept", "Kept", at)
		product := id(`SELECT MAX("id") FROM "product"`)
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "main", "Main", "branch", at)
		branch := id(`SELECT MAX("id") FROM "branch_or_tag"`)
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "parent_id", "created_at")
			VALUES (?, ?, ?, ?, ?, ?)`, product, "v1", "V1", "tag", branch, at)
		tag := id(`SELECT MAX("id") FROM "branch_or_tag"`)
		for _, name := range []string{"image", "bundle"} {
			exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
				VALUES (?, ?, ?, ?, ?)`, product, name, name, true, at)
		}
		exec(`INSERT INTO "party" ("kind") VALUES (?)`, "person")
		party := id(`SELECT MAX("id") FROM "party"`)
		exec(`INSERT INTO "person" ("party_id", "identity", "is_admin", "is_bootstrap", "admin_derived", "audits",
			"audits_derived", "email_source", "digest", "digest_unassigned", "created_at")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			party, "kept-person", false, false, false, false, false, "", false, false, at)
		person := id(`SELECT MAX("id") FROM "person"`)
		exec(`INSERT INTO "notification" ("person_id", "kind", "lifetime", "about", "body", "link", "private",
			"together", "attempts", "created_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			person, "kept", "event", "about-kept", "Something happened.", "/", false, "", 0, at)
		notification := id(`SELECT MAX("id") FROM "notification"`)
		exec(`INSERT INTO "chat_delivery" ("notification_id", "platform", "attempts", "first_seen")
			VALUES (?, ?, ?, ?)`, notification, "slack", 0, at)
		exec(`INSERT INTO "application_setting" ("name", "value", "updated_at") VALUES (?, ?, ?)`,
			"kept.setting", "40", at)

		seeded, err := keep(ctx, db)
		if err != nil {
			t.Fatal(err)
		}

		exec(`UPDATE "product" SET "display_name" = ? WHERE "id" = ?`, "Changed", product)
		exec(`DELETE FROM "variant" WHERE "name" = ?`, "bundle")
		exec(`DELETE FROM "notification" WHERE "id" = ?`, notification)
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "added", "Added", "branch", at)
		added := id(`SELECT MAX("id") FROM "branch_or_tag"`)
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "parent_id", "created_at")
			VALUES (?, ?, ?, ?, ?, ?)`, product, "v2", "V2", "tag", added, at)
		exec(`UPDATE "branch_or_tag" SET "parent_id" = ? WHERE "id" = ?`, added, tag)
		variant := id(`SELECT MIN("id") FROM "variant"`)
		exec(`INSERT INTO "build" ("branch_or_tag_id", "variant_id", "created_at") VALUES (?, ?, ?)`,
			added, variant, at)
		exec(`UPDATE "application_setting" SET "value" = ? WHERE "name" = ?`, "41", "kept.setting")
		exec(`INSERT INTO "application_setting" ("name", "value", "updated_at") VALUES (?, ?, ?)`,
			"added.setting", "1", at)

		if err := reconcile(ctx, db, seeded); err != nil {
			t.Fatalf("the changes were not undone row by row: %v", err)
		}
		again, err := keep(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := render(again), render(seeded); got != want {
			t.Errorf("reconciled, the rows read\n%s\nand the seed wrote\n%s", got, want)
		}
	})
}

// Every table referencing its own rows with no action on a delete has the
// column doing it emptied before one, and the list names no other; a table without an
// identifier is referenced by no foreign key, so emptying and writing it back
// whole reaches no other row.
//
// SQLite alone: the migrations are one list of statements for every engine.
func TestTheForeignKeysAreAsTheResetAssumes(t *testing.T) {
	Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		var keys []struct {
			From   string `bun:"from_table"`
			To     string `bun:"to_table"`
			Column string `bun:"from_column"`
			Action string `bun:"on_delete"`
		}
		if err := db.NewRaw(`SELECT "m"."name" AS "from_table", "f"."table" AS "to_table",
			"f"."from" AS "from_column", "f"."on_delete" AS "on_delete"
			FROM "sqlite_master" AS "m", pragma_foreign_key_list("m"."name") AS "f"
			WHERE "m"."type" = 'table'`).Scan(ctx, &keys); err != nil {
			t.Fatal(err)
		}
		if len(keys) == 0 {
			t.Fatal("no foreign key was found, so this checked nothing")
		}
		var identified []string
		if err := db.NewRaw(`SELECT "m"."name" FROM "sqlite_master" AS "m", pragma_table_info("m"."name") AS "c"
			WHERE "m"."type" = 'table' AND "c"."name" = 'id'`).Scan(ctx, &identified); err != nil {
			t.Fatal(err)
		}
		self := map[string]string{}
		for _, key := range keys {
			// A reference the engine empties or follows itself when its row
			// goes needs nothing first.
			if key.From == key.To && (key.Action == "NO ACTION" || key.Action == "RESTRICT") {
				self[key.From] = key.Column
			}
			if !slices.Contains(identified, key.To) {
				t.Errorf("%s references %s, which has no identifier, so writing %s back whole deletes "+
					"rows of %s first", key.From, key.To, key.To, key.From)
			}
		}
		for table, column := range self {
			if selfReferences[table] != column {
				t.Errorf("%s.%s references its own table and the reset does not empty it first", table, column)
			}
		}
		for table, column := range selfReferences {
			if self[table] != column {
				t.Errorf("the reset empties %s.%s first, which references nothing in its own table", table, column)
			}
		}
	})
}
