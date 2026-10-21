// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// probeReferencesLed refuses a removal from a table while another table
// points at it through a column no valid index leads with, and records each
// removal it lets through. PostgreSQL checks the references to a removed row
// by reading the table that holds them, so a column no index leads with is a
// read of that whole table for every row removed.
const probeReferencesLed = `CREATE FUNCTION "probe_references_led"() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
	bare text;
BEGIN
	SELECT string_agg("c"."conrelid"::regclass::text || '.' || "a"."attname", ', ')
	INTO bare
	FROM "pg_catalog"."pg_constraint" AS "c"
	JOIN "pg_catalog"."pg_attribute" AS "a"
		ON "a"."attrelid" = "c"."conrelid" AND "a"."attnum" = "c"."conkey"[1]
	WHERE "c"."contype" = 'f' AND "c"."confrelid" = TG_RELID
		AND NOT EXISTS (SELECT 1 FROM "pg_catalog"."pg_index" AS "i"
			WHERE "i"."indrelid" = "c"."conrelid" AND "i"."indkey"[0] = "c"."conkey"[1]
				AND "i"."indisvalid" AND "i"."indisready");
	IF bare IS NOT NULL THEN
		RAISE EXCEPTION 'rows of % were removed while % had no index leading with it', TG_TABLE_NAME, bare;
	END IF;
	INSERT INTO "probe_removed" ("removed_from") VALUES (TG_TABLE_NAME);
	RETURN NULL;
END
$$`

// Every statement a release upgrade runs to remove rows from a table that
// another table points at runs while each column pointing at it leads an
// index, on PostgreSQL. The v0.9.0 upgrade removes the components it merged
// and the nodes it joined, and indexes the columns pointing at both for the
// merge. An index an operator made by hand on one of those columns is left as
// it is, and the merge's own are gone once it is done.
//
// A trigger on every table, run once per statement, refuses the removal
// otherwise, so a removal the seed reaches no row of is checked as well.
func TestEveryReferenceToARowAnUpgradeRemovesIsIndexed(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		switch db.Server.Engine {
		case database.Postgres:
		case database.MySQL, database.MariaDB:
			t.Skip("every column a foreign key names is indexed by the engine itself")
		default:
			t.Skip("references are not checked while an upgrade runs, so a removal reads no other table")
		}
		ctx := t.Context()
		exec := func(stmt string) {
			t.Helper()
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("%v\n%s", err, stmt)
			}
		}
		names := func(query string) []string {
			t.Helper()
			var out []string
			if err := db.DB.NewRaw(query).Scan(ctx, &out); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
			return out
		}
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v070)
		exec(`CREATE TABLE "probe_removed" ("removed_from" text NOT NULL)`)
		exec(probeReferencesLed)
		// Removed before the database is emptied, which removes rows from
		// every table.
		unprobe := func() {
			for _, stmt := range []string{
				`DROP FUNCTION IF EXISTS "probe_references_led"() CASCADE`,
				`DROP TABLE IF EXISTS "probe_removed"`,
				`DROP INDEX IF EXISTS "operator_finding_component"`,
			} {
				if _, err := db.ExecContext(context.WithoutCancel(ctx), stmt); err != nil {
					t.Errorf("%v\n%s", err, stmt)
				}
			}
		}
		t.Cleanup(unprobe)
		// Every table the schema holds at each step, so a table an upgrade
		// makes is probed by the next one.
		probe := func() {
			t.Helper()
			tables := names(`SELECT "tablename" FROM "pg_catalog"."pg_tables"
				WHERE "schemaname" = CURRENT_SCHEMA() AND "tablename" <> 'probe_removed' ORDER BY 1`)
			if len(tables) == 0 {
				t.Fatal("no tables were found to probe, so this checked nothing")
			}
			for _, table := range tables {
				exec(`DROP TRIGGER IF EXISTS "probe_references_led" ON "` + table + `"`)
				exec(`CREATE TRIGGER "probe_references_led" BEFORE DELETE ON "` + table +
					`" FOR EACH STATEMENT EXECUTE FUNCTION "probe_references_led"()`)
			}
		}

		probe()
		dbtest.MigrateTo(t, db, v080)

		w := seedV080Images(t, ctx, db)
		exec(`CREATE INDEX "operator_finding_component" ON "finding" ("component_id")`)
		probe()
		dbtest.MigrateTo(t, db, v090)
		imagesAreMergedV090(t, ctx, db, w)

		probe()
		dbtest.MigrateTo(t, db, v0100)

		removed := names(`SELECT DISTINCT "removed_from" FROM "probe_removed" ORDER BY 1`)
		for _, table := range []string{"component", "graph_node"} {
			if !slices.Contains(removed, table) {
				t.Errorf("the upgrades removed no row of %s, so the probe on it checked nothing; removed from %v",
					table, removed)
			}
		}
		indexes := names(`SELECT "indexname" FROM "pg_catalog"."pg_indexes"
			WHERE "schemaname" = CURRENT_SCHEMA() AND ("indexname" LIKE 'v090\_merge\_%' OR "indexname" = 'operator_finding_component')`)
		if !slices.Equal(indexes, []string{"operator_finding_component"}) {
			t.Errorf("after the upgrades the database holds %v of the merge's and the operator's indexes, "+
				"want the operator's alone", indexes)
		}
		unprobe()
		leaveAtLatest(t, ctx, db)
	})
}
