// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// On PostgreSQL the baseline has the finding table vacuumed and analyzed after
// a small part of it changes, so an index-only scan after a nightly scan reads
// the index rather than the table.
func TestPostgresVacuumsFindingsAfterAFiftiethChanges(t *testing.T) {
	dbtest.Only(t, database.Postgres, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v090)

		var options []string
		rows, err := db.QueryContext(ctx, `SELECT unnest("c"."reloptions")
			FROM "pg_catalog"."pg_class" AS "c"
			JOIN "pg_catalog"."pg_namespace" AS "n" ON "n"."oid" = "c"."relnamespace"
			WHERE "n"."nspname" = CURRENT_SCHEMA() AND "c"."relname" = 'finding'`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var option string
			if err := rows.Scan(&option); err != nil {
				t.Fatal(err)
			}
			options = append(options, option)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		want := []string{
			"autovacuum_vacuum_scale_factor=0.02",
			"autovacuum_vacuum_insert_scale_factor=0.02",
			"autovacuum_analyze_scale_factor=0.01",
		}
		if strings.Join(options, " ") != strings.Join(want, " ") {
			t.Errorf("the finding table holds %q, want %q", options, want)
		}
	})
}
