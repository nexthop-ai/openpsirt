// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// describe is a database's schema as lines of text, one per column, index and
// constraint, sorted so two can be compared as sets.
//
// A column's position is left out. Migration 37 adds a column at the end of a
// table where v0.2.0's declaration puts it in the middle, and no query here
// reads a column by position. Everything else the engine reports about a
// column is in: its type as the engine spells it, whether it takes a null, its
// default, and on MySQL and MariaDB its collation and the table's options.
func describe(t *testing.T, ctx context.Context, db *database.DB) []string {
	t.Helper()
	var queries []string
	switch db.Server.Engine {
	case database.Postgres:
		queries = []string{
			`SELECT 'column ' || "table_name" || '.' || "column_name" || ' ' || "udt_name" ||
				COALESCE('(' || "character_maximum_length" || ')', '') ||
				' null=' || "is_nullable" || ' identity=' || "is_identity" ||
				' default=' || COALESCE("column_default", '-')
			 FROM "information_schema"."columns" WHERE "table_schema" = CURRENT_SCHEMA()`,
			`SELECT 'index ' || "tablename" || ' ' || "indexdef"
			 FROM "pg_catalog"."pg_indexes" WHERE "schemaname" = CURRENT_SCHEMA()`,
			`SELECT 'constraint ' || "c"."relname" || ' ' || "k"."conname" || ' ' ||
				pg_get_constraintdef("k"."oid")
			 FROM "pg_catalog"."pg_constraint" AS "k"
			 JOIN "pg_catalog"."pg_class" AS "c" ON "c"."oid" = "k"."conrelid"
			 JOIN "pg_catalog"."pg_namespace" AS "n" ON "n"."oid" = "c"."relnamespace"
			 WHERE "n"."nspname" = CURRENT_SCHEMA()`,
		}
	case database.MySQL, database.MariaDB:
		queries = []string{
			`SELECT CONCAT('table ', "TABLE_NAME", ' ', COALESCE("ENGINE", '-'), ' ',
				COALESCE("ROW_FORMAT", '-'), ' ', COALESCE("TABLE_COLLATION", '-'))
			 FROM "information_schema"."TABLES" WHERE "TABLE_SCHEMA" = DATABASE()`,
			`SELECT CONCAT('column ', "TABLE_NAME", '.', "COLUMN_NAME", ' ', "COLUMN_TYPE",
				' null=', "IS_NULLABLE", ' default=', COALESCE("COLUMN_DEFAULT", '-'),
				' extra=', "EXTRA", ' collation=', COALESCE("COLLATION_NAME", '-'))
			 FROM "information_schema"."COLUMNS" WHERE "TABLE_SCHEMA" = DATABASE()`,
			`SELECT CONCAT('index ', "TABLE_NAME", ' ', "INDEX_NAME", ' unique=', 1 - "NON_UNIQUE", ' (',
				GROUP_CONCAT("COLUMN_NAME" ORDER BY "SEQ_IN_INDEX" SEPARATOR ', '), ')')
			 FROM "information_schema"."STATISTICS" WHERE "TABLE_SCHEMA" = DATABASE()
			 GROUP BY "TABLE_NAME", "INDEX_NAME", "NON_UNIQUE"`,
			`SELECT CONCAT('foreign key ', "k"."TABLE_NAME", ' ', "k"."CONSTRAINT_NAME", ' (',
				GROUP_CONCAT("k"."COLUMN_NAME" ORDER BY "k"."ORDINAL_POSITION" SEPARATOR ', '), ') -> ',
				MAX("k"."REFERENCED_TABLE_NAME"), ' (',
				GROUP_CONCAT("k"."REFERENCED_COLUMN_NAME" ORDER BY "k"."ORDINAL_POSITION" SEPARATOR ', '),
				') ', MAX("r"."DELETE_RULE"))
			 FROM "information_schema"."KEY_COLUMN_USAGE" AS "k"
			 JOIN "information_schema"."REFERENTIAL_CONSTRAINTS" AS "r"
			   ON "r"."CONSTRAINT_SCHEMA" = "k"."CONSTRAINT_SCHEMA"
			  AND "r"."CONSTRAINT_NAME" = "k"."CONSTRAINT_NAME"
			  AND "r"."TABLE_NAME" = "k"."TABLE_NAME"
			 WHERE "k"."TABLE_SCHEMA" = DATABASE() AND "k"."REFERENCED_TABLE_NAME" IS NOT NULL
			 GROUP BY "k"."TABLE_NAME", "k"."CONSTRAINT_NAME"`,
		}
	case database.SQLite:
		return describeSQLite(t, ctx, db)
	default:
		t.Fatalf("no description of a schema on %s", db.Server.Engine)
	}

	var lines []string
	for _, q := range queries {
		lines = append(lines, queryLines(t, ctx, db.DB.DB, q)...)
	}
	slices.Sort(lines)
	return lines
}

// describeSQLite reads the same from SQLite's pragmas, which report per table.
//
// SQLite does not name a foreign key or a unique constraint anywhere it can be
// read back, so those lines carry what is constrained rather than a name.
func describeSQLite(t *testing.T, ctx context.Context, db *database.DB) []string {
	t.Helper()
	conn := db.DB.DB
	tables := queryLines(t, ctx, conn,
		`SELECT "name" FROM "sqlite_master" WHERE "type" = 'table' AND "name" NOT LIKE 'sqlite_%'`)
	var lines []string
	for _, table := range tables {
		lines = append(lines, queryLines(t, ctx, conn, fmt.Sprintf(
			`SELECT 'column %[1]s.' || "name" || ' ' || "type" || ' notnull=' || "notnull" ||
				' default=' || COALESCE("dflt_value", '-') || ' pk=' || "pk"
			 FROM pragma_table_info('%[1]s')`, table))...)
		lines = append(lines, queryLines(t, ctx, conn, fmt.Sprintf(
			`SELECT 'foreign key %[1]s (' || group_concat("from", ', ') || ') -> ' || "table" ||
				' (' || group_concat("to", ', ') || ') ' || "on_delete"
			 FROM pragma_foreign_key_list('%[1]s') GROUP BY "id"`, table))...)
		lines = append(lines, queryLines(t, ctx, conn, fmt.Sprintf(
			`SELECT 'index %[1]s ' || CASE WHEN "l"."origin" = 'c' THEN "l"."name" ELSE "l"."origin" END ||
				' unique=' || "l"."unique" || ' (' ||
				(SELECT group_concat("i"."name", ', ') FROM pragma_index_info("l"."name") AS "i") || ')'
			 FROM pragma_index_list('%[1]s') AS "l"`, table))...)
	}
	slices.Sort(lines)
	return lines
}

func queryLines(t *testing.T, ctx context.Context, conn *sql.DB, query string) []string {
	t.Helper()
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		t.Fatalf("describe the schema: %v\n%s", err, query)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("describe the schema: %v", err)
		}
		out = append(out, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("describe the schema: %v", err)
	}
	return out
}
