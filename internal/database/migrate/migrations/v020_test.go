// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// v010 is the last migration the v0.1.0 release shipped.
const v010 = 36

// A database the v0.1.0 release built, holding a row in every table, is
// upgraded into exactly the schema a fresh install makes, and every value it
// held is still there. Rolled back, it is v0.1.0's schema again, and upgraded
// a second time it is the fresh install's.
func TestAV010DatabaseUpgradesToTheFreshSchemaKeepingItsRows(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		fresh := describe(t, ctx, db)
		if len(fresh) == 0 {
			t.Fatal("the fresh schema described as nothing, so nothing is compared")
		}

		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v010)
		released := describe(t, ctx, db)
		shippedSchema(t, db.Server.Engine, released)
		seed(t, ctx, db)
		before := snapshot(t, ctx, db)

		start := time.Now()
		if err := schema.Up(ctx, db, quiet()); err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		t.Logf("%s: upgraded in %v", db.Server.Engine, time.Since(start))

		if diff := setDiff(fresh, describe(t, ctx, db)); diff != "" {
			t.Errorf("the upgraded schema differs from a fresh install's:\n%s", diff)
		}
		survived(t, ctx, db, before)
		moved(t, ctx, db)

		version, err := schema.Version(ctx, db)
		if err != nil {
			t.Fatalf("read the version: %v", err)
		}
		wanted, err := schema.Expected()
		if err != nil {
			t.Fatalf("read the expected version: %v", err)
		}
		if version != wanted {
			t.Errorf("the upgrade left version %d and this build expects %d", version, wanted)
		}
		// A second start finds nothing to do.
		if err := schema.Up(ctx, db, quiet()); err != nil {
			t.Fatalf("a start after the upgrade: %v", err)
		}

		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll the upgrade back: %v", err)
		}
		if diff := setDiff(released, describe(t, ctx, db)); diff != "" {
			t.Errorf("rolled back, the schema differs from v0.1.0's:\n%s", diff)
		}
		returned(t, ctx, db, before)
		if err := schema.Up(ctx, db, quiet()); err != nil {
			t.Fatalf("upgrade again: %v", err)
		}
		if diff := setDiff(fresh, describe(t, ctx, db)); diff != "" {
			t.Errorf("upgraded a second time, the schema differs from a fresh install's:\n%s", diff)
		}
		dbtest.Reset(t, db)
	})
}

// rollBack takes a migrated database back to nothing.
func rollBack(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	dbtest.Reset(t, db)
	for {
		at, err := schema.Version(ctx, db)
		if err != nil {
			t.Fatalf("version: %v", err)
		}
		if at == 0 {
			return
		}
		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll back from %d: %v", at, err)
		}
	}
}

// column is one column of the v0.1.0 schema as the engine reports it.
type column struct {
	name      string
	kind      string // int, bool, text, date, time, bytes
	width     int    // zero where the engine states none
	nullable  bool
	generated bool
	refers    string // the table a foreign key names, where one does
}

var widthOf = regexp.MustCompile(`\((\d+)\)`)

func classify(spelled string) (string, int) {
	s := strings.ToLower(spelled)
	width := 0
	if m := widthOf.FindStringSubmatch(s); m != nil {
		_, _ = fmt.Sscan(m[1], &width)
	}
	switch {
	case s == "tinyint(1)" || strings.HasPrefix(s, "bool"):
		return "bool", 0
	case strings.Contains(s, "int"):
		return "int", 0
	case s == "date":
		return "date", 0
	case strings.Contains(s, "time"):
		return "time", 0
	case strings.Contains(s, "blob") || s == "bytea":
		return "bytes", 0
	}
	return "text", width
}

// columns reads every table's columns, and the tables each points at.
func columns(t *testing.T, ctx context.Context, db *database.DB) map[string][]column {
	t.Helper()
	type raw struct {
		Table, Column, Spelled string
		Nullable, Generated    bool
	}
	var rows []raw
	var refs []struct{ Table, Column, Refers string }
	var err error
	switch db.Server.Engine {
	case database.Postgres:
		err = db.NewRaw(`SELECT "table_name" AS "table", "column_name" AS "column",
				"udt_name" || COALESCE('(' || "character_maximum_length" || ')', '') AS "spelled",
				"is_nullable" = 'YES' AS "nullable", "is_identity" = 'YES' AS "generated"
			FROM "information_schema"."columns" WHERE "table_schema" = CURRENT_SCHEMA()`).Scan(ctx, &rows)
		if err == nil {
			err = db.NewRaw(`SELECT "c"."relname" AS "table", "a"."attname" AS "column", "p"."relname" AS "refers"
				FROM "pg_catalog"."pg_constraint" AS "k"
				JOIN "pg_catalog"."pg_class" AS "c" ON "c"."oid" = "k"."conrelid"
				JOIN "pg_catalog"."pg_class" AS "p" ON "p"."oid" = "k"."confrelid"
				JOIN "pg_catalog"."pg_namespace" AS "n" ON "n"."oid" = "c"."relnamespace"
				JOIN "pg_catalog"."pg_attribute" AS "a"
				  ON "a"."attrelid" = "k"."conrelid" AND "a"."attnum" = ANY("k"."conkey")
				WHERE "k"."contype" = 'f' AND "n"."nspname" = CURRENT_SCHEMA()`).Scan(ctx, &refs)
		}
	case database.MySQL, database.MariaDB:
		err = db.NewRaw(`SELECT "TABLE_NAME" AS "table", "COLUMN_NAME" AS "column", "COLUMN_TYPE" AS "spelled",
				"IS_NULLABLE" = 'YES' AS "nullable", "EXTRA" LIKE '%auto_increment%' AS "generated"
			FROM "information_schema"."COLUMNS" WHERE "TABLE_SCHEMA" = DATABASE()`).Scan(ctx, &rows)
		if err == nil {
			err = db.NewRaw(`SELECT "TABLE_NAME" AS "table", "COLUMN_NAME" AS "column",
					"REFERENCED_TABLE_NAME" AS "refers"
				FROM "information_schema"."KEY_COLUMN_USAGE"
				WHERE "TABLE_SCHEMA" = DATABASE() AND "REFERENCED_TABLE_NAME" IS NOT NULL`).Scan(ctx, &refs)
		}
	case database.SQLite:
		err = db.NewRaw(`SELECT "m"."name" AS "table", "c"."name" AS "column", "c"."type" AS "spelled",
				"c"."notnull" = 0 AND "c"."pk" = 0 AS "nullable", "c"."pk" = 1 AND "c"."name" = 'id' AS "generated"
			FROM "sqlite_master" AS "m", pragma_table_info("m"."name") AS "c"
			WHERE "m"."type" = 'table' AND "m"."name" NOT LIKE 'sqlite_%'`).Scan(ctx, &rows)
		if err == nil {
			err = db.NewRaw(`SELECT "m"."name" AS "table", "f"."from" AS "column", "f"."table" AS "refers"
				FROM "sqlite_master" AS "m", pragma_foreign_key_list("m"."name") AS "f"
				WHERE "m"."type" = 'table'`).Scan(ctx, &refs)
		}
	}
	if err != nil {
		t.Fatalf("read the columns: %v", err)
	}
	refers := map[[2]string]string{}
	for _, r := range refs {
		refers[[2]string{r.Table, r.Column}] = r.Refers
	}
	out := map[string][]column{}
	for _, r := range rows {
		if r.Table == "goose_db_version" {
			continue
		}
		kind, width := classify(r.Spelled)
		out[r.Table] = append(out[r.Table], column{
			name: r.Column, kind: kind, width: width, nullable: r.Nullable,
			generated: r.Generated, refers: refers[[2]string{r.Table, r.Column}],
		})
	}
	if len(out) == 0 {
		t.Fatal("the v0.1.0 schema read as no tables")
	}
	return out
}

// overrides are the values the upgrade reads meaning into, where a made-up
// one would not reach the branch that moves it.
var overrides = map[string]any{
	"finding.kind":               "entered",
	"vulnerability.identifier":   "CVE-2025-1111",
	"vulnerability_weakness.cwe": "CWE-79",
	"vex_statement.purl":         "pkg:deb/debian/openssl@3.0.11-1%2Bdeb12u2?arch=amd64",
	"product.name":               "widget",
	"advisory_issuance.ordinal":  int64(1),
}

// seed writes a row into every table of the v0.1.0 schema, each after the
// tables it points at, every column holding a value. A foreign key points at
// the first row of the table it names, which is the one this wrote.
func seed(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	tables := columns(t, ctx, db)
	done := map[string]bool{}
	when := time.Date(2025, 11, 3, 9, 30, 0, 0, time.UTC)
	for len(done) < len(tables) {
		progressed := false
		for _, name := range sortedKeys(tables) {
			if done[name] || !ready(tables[name], name, done) {
				continue
			}
			var names, marks []string
			var args []any
			for i, c := range tables[name] {
				if c.generated {
					continue
				}
				names = append(names, `"`+c.name+`"`)
				marks = append(marks, "?")
				args = append(args, valueFor(name, c, i, when))
			}
			if _, err := db.ExecContext(ctx, `INSERT INTO "`+name+`" (`+strings.Join(names, ", ")+
				`) VALUES (`+strings.Join(marks, ", ")+`)`, args...); err != nil {
				t.Fatalf("seed %s: %v", name, err)
			}
			done[name] = true
			progressed = true
		}
		if !progressed {
			t.Fatalf("the tables left point at each other: %v", missing(tables, done))
		}
	}

	// Identifiers a fresh table would not generate, so that keeping them is
	// something the upgrade does rather than something it happens into.
	exec(t, ctx, db, `UPDATE "disclosure_extension" SET "id" = 7`)
	exec(t, ctx, db, `UPDATE "advisory_issuance" SET "id" = 7`)

	// The flaw recorded here, refiled under a CVE after it was issued: the
	// name it was minted and issued under is kept among its aliases.
	exec(t, ctx, db, `INSERT INTO "vulnerability_alias" ("vulnerability_id", "identifier", "identifier_folded")
		VALUES (1, 'WIDGET-2025-123456', 'widget-2025-123456')`)

	// An issue a scanner reported, classified, and recorded here by nobody.
	copyRow(t, ctx, db, tables["vulnerability"], "vulnerability", map[string]any{
		"identifier": "CVE-2025-2222", "identifier_folded": "cve-2025-2222"})
	exec(t, ctx, db, `INSERT INTO "vulnerability_weakness" ("vulnerability_id", "cwe") VALUES (2, 'CWE-89')`)
	copyRow(t, ctx, db, tables["finding"], "finding", map[string]any{"vulnerability_id": 2, "kind": "vulnerability"})

	// A second weakness named after the first, a second issuance of the same
	// advisory, and a statement naming no version.
	exec(t, ctx, db, `INSERT INTO "vulnerability_weakness" ("vulnerability_id", "cwe") VALUES (1, 'CWE-20')`)
	exec(t, ctx, db, `INSERT INTO "advisory_issuance" ("id", "product_id", "vulnerability_id", "ordinal", "digest",
		"summary", "issued_by", "issued_at") VALUES (8, 1, 1, 2, 'second', NULL, 1, ?)`, when.Add(time.Hour))
	exec(t, ctx, db, `INSERT INTO "vex_statement" ("product_id", "publisher", "vulnerability", "purl",
		"component", "status", "statement", "document", "digest", "uploaded_by", "uploaded_at", "superseded_at")
		SELECT "product_id", "publisher", 'CVE-2', 'pkg:generic/zlib', "component", "status", "statement",
		"document", "digest", "uploaded_by", "uploaded_at", "superseded_at" FROM "vex_statement"`)
}

// copyRow writes a second row into a table, copied from its first with some
// columns replaced.
func copyRow(t *testing.T, ctx context.Context, db *database.DB, cols []column, table string, with map[string]any) {
	t.Helper()
	var names, values []string
	var args []any
	for _, c := range cols {
		if c.generated {
			continue
		}
		names = append(names, `"`+c.name+`"`)
		if v, ok := with[c.name]; ok {
			values = append(values, "?")
			args = append(args, v)
			continue
		}
		values = append(values, `"`+c.name+`"`)
	}
	exec(t, ctx, db, `INSERT INTO "`+table+`" (`+strings.Join(names, ", ")+`) SELECT `+
		strings.Join(values, ", ")+` FROM "`+table+`" WHERE "id" = 1`, args...)
}

func ready(cols []column, name string, done map[string]bool) bool {
	for _, c := range cols {
		if c.refers != "" && c.refers != name && !done[c.refers] {
			return false
		}
	}
	return true
}

func valueFor(table string, c column, i int, when time.Time) any {
	if v, ok := overrides[table+"."+c.name]; ok {
		return v
	}
	if c.refers != "" {
		if c.refers == table {
			return nil
		}
		return int64(1)
	}
	switch c.kind {
	case "int":
		return int64(1)
	case "bool":
		return true
	case "date":
		return when.Truncate(24 * time.Hour)
	case "time":
		return when
	case "bytes":
		return []byte("seed")
	}
	v := fmt.Sprintf("%s%d", c.name, i)
	if c.width > 0 && len(v) > c.width {
		v = v[:c.width]
	}
	return v
}

func exec(t *testing.T, ctx context.Context, db *database.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, query, args...); err != nil {
		t.Fatalf("%v\n%s", err, query)
	}
}

// snapshot reads every column of every table, as text.
func snapshot(t *testing.T, ctx context.Context, db *database.DB) map[string][]map[string]string {
	t.Helper()
	out := map[string][]map[string]string{}
	for table, cols := range columns(t, ctx, db) {
		var names []string
		for _, c := range cols {
			names = append(names, c.name)
		}
		out[table] = read(t, ctx, db, table, names)
	}
	return out
}

func read(t *testing.T, ctx context.Context, db *database.DB, table string, names []string) []map[string]string {
	t.Helper()
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = `"` + n + `"`
	}
	order := quoted[0]
	if slices.Contains(names, "id") {
		order = `"id"`
	}
	rows, err := db.QueryContext(ctx, `SELECT `+strings.Join(quoted, ", ")+` FROM "`+table+`" ORDER BY `+order)
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	var out []map[string]string
	for rows.Next() {
		values := make([]any, len(names))
		pointers := make([]any, len(names))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		row := map[string]string{}
		for i, n := range names {
			row[n] = text(values[i])
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	return out
}

func text(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		return string(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprint(v)
}

// survived checks every value the release held is still where it was, in
// every table the upgrade keeps.
func survived(t *testing.T, ctx context.Context, db *database.DB, before map[string][]map[string]string) {
	t.Helper()
	replaced := map[string]bool{"disclosure_extension": true, "advisory_issuance": true}
	checked := 0
	for table, rows := range before {
		if replaced[table] {
			continue
		}
		if len(rows) == 0 {
			t.Errorf("%s held no rows before the upgrade, so nothing was checked in it", table)
			continue
		}
		after := read(t, ctx, db, table, sortedKeys(rows[0]))
		if len(after) != len(rows) {
			t.Errorf("%s held %d rows and holds %d", table, len(rows), len(after))
			continue
		}
		for i := range rows {
			for column, was := range rows[i] {
				if now := after[i][column]; now != was {
					t.Errorf("%s.%s was %q and is %q", table, column, was, now)
				}
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no table was checked")
	}
}

// moved checks what the upgrade wrote where the release's rows changed shape,
// or took a value a column v0.1.0 did not have.
func moved(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	one := func(query string, args ...any) string {
		t.Helper()
		var v any
		if err := db.QueryRowContext(ctx, query, args...).Scan(&v); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
		return text(v)
	}
	every := func(table, where string, args ...any) {
		t.Helper()
		all := one(`SELECT COUNT(*) FROM "` + table + `"`)
		if got := one(`SELECT COUNT(*) FROM "`+table+`" WHERE `+where, args...); got != all || all == "0" {
			t.Errorf("%s of %s rows of %s hold %s", got, all, table, where)
		}
	}

	if got := one(`SELECT "act" FROM "disclosure_movement" WHERE "id" = 7`); got != "extension" {
		t.Errorf("the embargo extension moved across as %q", got)
	}
	if got := one(`SELECT "cwe" FROM "vulnerability_weakness" WHERE "is_primary" = ?`, true); got != "CWE-79" {
		t.Errorf("the weakness named first is not the primary one; %s is", got)
	}
	if got := one(`SELECT COUNT(*) FROM "vulnerability_weakness" WHERE "is_primary" = ?`, true); got != "1" {
		t.Errorf("%s weaknesses are primary, and only the flaw recorded here names one", got)
	}
	every("finding", `"urgency_exploited_here" = ?`, false)
	every("notification", `"together" = ''`)
	every("flaw_report", `"evaluated_at" = "recorded_at" AND "evaluated_by" = "recorded_by"`)

	reference := one(`SELECT "reference" FROM "flaw_report"`)
	if !regexp.MustCompile(`^WIDGET-R-2025-\d{6}$`).MatchString(reference) {
		t.Errorf("a report was named %q", reference)
	}
	abouts := read(t, ctx, db, "vex_statement", []string{"id", "source", "document_id", "about"})
	if len(abouts) != 2 || abouts[0]["about"] != "3.0.11-1+deb12u2" || abouts[1]["about"] != "" ||
		abouts[0]["source"] != "vex" || abouts[0]["document_id"] != "" {
		t.Errorf("the statements moved across as %v", abouts)
	}

	opened := read(t, ctx, db, "finding", []string{"opened_at"})
	advisories := read(t, ctx, db, "advisory", []string{"id", "identifier", "identifier_folded",
		"minted_year", "mint_number", "edition_id", "released_from"})
	if len(advisories) != 1 || advisories[0]["identifier"] != "WIDGET-2025-123456" ||
		advisories[0]["identifier_folded"] != "widget-2025-123456" || advisories[0]["minted_year"] != "0" ||
		advisories[0]["released_from"] != opened[0]["opened_at"] || advisories[0]["edition_id"] == "NULL" {
		t.Errorf("the advisory moved across as %v, from a flaw first recorded %s", advisories, opened[0]["opened_at"])
	}
	issued := read(t, ctx, db, "advisory_issuance", []string{"id", "ordinal", "document", "digest",
		"summary", "edition_id"})
	if len(issued) != 2 || issued[0]["id"] != "7" || issued[1]["id"] != "8" ||
		issued[0]["ordinal"] != "1" || issued[1]["ordinal"] != "2" ||
		issued[0]["summary"] == "NULL" || issued[1]["summary"] != "NULL" || issued[1]["digest"] != "second" ||
		issued[0]["document"] != "NULL" || issued[1]["document"] != "NULL" ||
		issued[0]["edition_id"] != advisories[0]["edition_id"] {
		t.Errorf("the issuances moved across as %v", issued)
	}
	if got := one(`SELECT COUNT(*) FROM "advisory_issue" WHERE "product_id" = 1 AND "vulnerability_id" = 1`); got != "1" {
		t.Errorf("the advisory names its issue %s times", got)
	}

	// A table whose rows kept their identifiers generates new ones past them.
	exec(t, ctx, db, `INSERT INTO "disclosure_movement" ("vulnerability_id", "product_id", "act", "was",
		"until", "reason", "asked_by", "asked_at", "needs_approval") VALUES (1, 1, 'shortening', ?, ?, 'r', 1, ?, ?)`,
		time.Now(), time.Now(), time.Now(), false)
	exec(t, ctx, db, `INSERT INTO "advisory_issuance" ("advisory_id", "ordinal", "edition_id", "document",
		"digest", "issued_by", "issued_at") VALUES (?, 3, ?, '{}', 'third', 1, ?)`,
		advisories[0]["id"], advisories[0]["edition_id"], time.Now())
	for table, carried := range map[string]int{"disclosure_movement": 7, "advisory_issuance": 8} {
		if got := one(`SELECT COUNT(*) FROM "`+table+`" WHERE "id" > ?`, carried); got != "1" {
			t.Errorf("%s generated no identifier past the ones carried across", table)
		}
	}

	// A second advisory about the same issue in the same product, which v0.1.0
	// has one sequence of issuances for.
	exec(t, ctx, db, `INSERT INTO "advisory" ("identifier", "identifier_folded", "minted_year", "mint_number",
		"minted_at", "minted_by") VALUES ('PSIRT-2026-0001', 'psirt-2026-0001', 2026, 1, ?, 1)`, time.Now())
	second := one(`SELECT "id" FROM "advisory" WHERE "identifier_folded" = 'psirt-2026-0001'`)
	exec(t, ctx, db, `INSERT INTO "advisory_edition" ("advisory_id", "ordinal", "written_by", "written_at")
		VALUES (?, 1, 1, ?)`, second, time.Now())
	edition := one(`SELECT "id" FROM "advisory_edition" WHERE "advisory_id" = ?`, second)
	exec(t, ctx, db, `INSERT INTO "advisory_issue" ("advisory_id", "product_id", "vulnerability_id",
		"added_at", "added_by") VALUES (?, 1, 1, ?, 1)`, second, time.Now())
	exec(t, ctx, db, `INSERT INTO "advisory_issuance" ("advisory_id", "ordinal", "edition_id", "document",
		"digest", "issued_by", "issued_at") VALUES (?, 1, ?, '{}', 'other', 1, ?)`, second, edition, time.Now())
}

// returned checks what the rollback put back in the tables it recreated: every
// row the release held, as it held it, and identifiers generated past them.
func returned(t *testing.T, ctx context.Context, db *database.DB, before map[string][]map[string]string) {
	t.Helper()
	for _, table := range []string{"disclosure_extension", "advisory_issuance"} {
		was := before[table]
		if len(was) == 0 {
			t.Fatalf("%s held nothing before the upgrade, so nothing is checked", table)
		}
		now := read(t, ctx, db, table, sortedKeys(was[0]))
		byID := map[string]map[string]string{}
		for _, row := range now {
			byID[row["id"]] = row
		}
		for _, row := range was {
			back, ok := byID[row["id"]]
			if !ok {
				t.Errorf("%s %s did not come back", table, row["id"])
				continue
			}
			for column, value := range row {
				if back[column] != value {
					t.Errorf("%s %s.%s was %q and came back %q", table, row["id"], column, value, back[column])
				}
			}
		}
	}
	// The shortening has no place in v0.1.0, and the second advisory about
	// the same issue gives way to the first; the first's third issuance comes
	// back with it.
	for table, want := range map[string]int{"disclosure_extension": 1, "advisory_issuance": 3} {
		if got := len(read(t, ctx, db, table, []string{"id"})); got != want {
			t.Errorf("%s holds %d rows after the rollback, not %d", table, got, want)
		}
	}
	highest := map[string]string{}
	for _, table := range []string{"disclosure_extension", "advisory_issuance"} {
		var id any
		if err := db.QueryRowContext(ctx, `SELECT MAX("id") FROM "`+table+`"`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		highest[table] = text(id)
	}
	exec(t, ctx, db, `INSERT INTO "disclosure_extension" ("vulnerability_id", "product_id", "was", "until",
		"reason", "asked_by", "asked_at", "needs_approval") VALUES (1, 1, ?, ?, 'r', 1, ?, ?)`,
		time.Now(), time.Now(), time.Now(), false)
	exec(t, ctx, db, `INSERT INTO "advisory_issuance" ("product_id", "vulnerability_id", "ordinal", "digest",
		"issued_by", "issued_at") VALUES (1, 1, 9, 'again', 1, ?)`, time.Now())
	for table, top := range highest {
		var past any
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM "`+table+`" WHERE "id" > ?`, top).Scan(&past); err != nil {
			t.Fatal(err)
		}
		if text(past) != "1" {
			t.Errorf("%s generated no identifier past the ones returned to it", table)
		}
	}
}

// shippedSchema holds what migrations 1 to 36 build to what they built when
// v0.1.0 was tagged, which the files alone do not: the column spellings and
// widths they use are read from helpers a later change is free to edit.
//
// The expected schema was captured from the tag's migrations on each engine.
func shippedSchema(t *testing.T, engine database.Engine, got []string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", "v010-schema-"+string(engine)+".txt"))
	if err != nil {
		t.Fatalf("read what v0.1.0 built on %s: %v", engine, err)
	}
	lines := strings.Split(strings.TrimRight(string(want), "\n"), "\n")
	if diff := setDiff(lines, got); diff != "" {
		t.Errorf("migrations 1 to 36 no longer build what v0.1.0 built on %s:\n%s", engine, diff)
	}
}

func setDiff(want, got []string) string {
	var b strings.Builder
	for _, line := range want {
		if !slices.Contains(got, line) {
			fmt.Fprintf(&b, "  missing: %s\n", line)
		}
	}
	for _, line := range got {
		if !slices.Contains(want, line) {
			fmt.Fprintf(&b, "  extra:   %s\n", line)
		}
	}
	return b.String()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func missing(tables map[string][]column, done map[string]bool) []string {
	var out []string
	for name := range tables {
		if !done[name] {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}
