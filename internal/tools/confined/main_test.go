// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Four engines are supported and engine-specific code lives in one package
// (REQ-71). This gate reads text rather than queries, so a sixth site arrives
// announced rather than discovered — and it had no test, which makes its exit
// code the only evidence that it still recognizes anything.

func TestWhatCountsAsAskingAnEngineDirectly(t *testing.T) {
	for _, c := range []struct {
		what string
		line string
		want bool
	}{
		{"a named engine", "\tif db.Engine == database.Postgres {", true},
		{"MySQL's own error type", "\tvar fault *mysql.MySQLError", true},
		{"PostgreSQL's own error type", "\tvar fault *pgconn.PgError", true},
		{"SQLite's own error type", "\tvar lite *sqlite.Error", true},
		{"bun's name for an engine", "\tif db.Dialect().Name() == dialect.PG {", true},
		{"bun's name for an engine, alone", "\tcase dialect.SQLite:", true},
		{
			// Written without naming a constant, which is how the one live
			// branch in the tree spells it — and it was not looked for at all,
			// so those three lines pasted into a store package would have
			// passed.
			"asking the handle what it is", "\tswitch db.Dialect().Name() {", true,
		},
		{"bun's spelling of an upsert", "\t\tq = q.On(\"CONFLICT\").Ignore()", true},
		{"an upsert written as SQL", "\t`INSERT ... ON CONFLICT DO NOTHING`", true},
		{"MySQL's spelling of the same", "\t`INSERT ... ON DUPLICATE KEY UPDATE`", true},
		{"a case-insensitive match only two of them have", "\tWhere(\"name ILIKE ?\", x)", true},
		{"SQLite's own clock", "\t`SELECT julianday('now')`", true},
		{"MySQL's own interval", "\t`SELECT TIMESTAMPDIFF(SECOND, a, b)`", true},
		{"PostgreSQL's own interval", "\t`SELECT EXTRACT(EPOCH FROM a - b)`", true},
		{"a row lock three of them have", "\t`SELECT 1 FOR UPDATE`", true},
		{"PostgreSQL's lock", "\t`SELECT pg_advisory_lock(1)`", true},
		{"MySQL's lock", "\t`SELECT GET_LOCK('x', 1)`", true},
		{"an engine compared as a value", "\tif db.Server.Engine == other {", true},
		{"an engine compared by its name", "\tif r.engine != \"sqlite\" {", true},
		{"an engine's name compared the other way round", "\tif \"postgres\" == engine {", true},
		{"a switch on an engine's name", "\tcase \"mariadb\":", true},
		{"a switch on an engine's name second in its list", "\tcase other, \"mysql\":", true},
		{"a local engine compared", "\tif engine == want {", true},
		{"a switch on another name", "\tcase \"postgresql-ish\", \"x\":", false},
		{"a row handed back, which MySQL cannot", "\t`INSERT INTO t (a) VALUES (?) RETURNING \"id\"`", true},
		{"the builder asking for a row back", "\tq.Returning(\"id\")", true},
		{"PostgreSQL's aggregate of text", "\t`SELECT STRING_AGG(name, ',')`", true},
		{"MySQL's aggregate of text", "\t`SELECT GROUP_CONCAT(name)`", true},
		{"MySQL's last identifier", "\t`SELECT LAST_INSERT_ID()`", true},
		{"PostgreSQL's array expansion", "\t`SELECT * FROM unnest(?)`", true},
		{"a statistics refresh", "\t`ANALYZE \"finding\"`", true},
		{"a catalog", "\t`SELECT 1 FROM information_schema.tables`", true},
		{"PostgreSQL's catalog", "\t`SELECT 1 FROM pg_catalog.pg_class`", true},
		{"SQLite's catalog", "\t`SELECT name FROM sqlite_master`", true},
		{"PostgreSQL's cast", "\t`SELECT ?::timestamptz`", true},

		{"ordinary go", "\tfor _, row := range rows {", false},
		{"a portable query", "\tdb.NewSelect().Model(&x).Where(\"id = ?\", id)", false},
		{"a word that merely contains one", "\t// the postgresql documentation", false},
		{"an insert asking for no row back", "\tq.Returning(\"\").Exec(ctx)", false},
		{"an engine's role asked of the database package", "\tif db.Server.Engine.IsProduction() {", false},
		{"an address with a double colon", "\taddr := \"[::1]:80\"", false},
		{"a name that merely holds an engine's", "\tname := \"postgres-data\"", false},
	} {
		if got := asks(c.line, engineConstant("database")) != ""; got != c.want {
			t.Errorf("%s: reported=%v, want %v: %q", c.what, got, c.want, c.line)
		}
	}
}

func TestChoosingWhichEngineATestRunsOnIsNotABranch(t *testing.T) {
	// `dbtest.Only(t, database.SQLite, …)` says this question has the same
	// answer everywhere and is asked once, which is the distinction the whole
	// rule is about.
	for _, c := range []struct {
		what string
		line string
		want bool
	}{
		{"one engine chosen for a test", "\tdbtest.Only(t, database.SQLite, func(t *testing.T) {", true},
		{"two engines chosen", "\tdbtest.Two(t, database.Postgres, fn)", true},
		{"a branch on the engine", "\tif engine == database.MySQL {", false},
		{"the harness not being named", "\tOnly(database.SQLite)", false},
	} {
		if got := selecting.MatchString(c.line); got != c.want {
			t.Errorf("%s: selecting=%v, want %v: %q", c.what, got, c.want, c.line)
		}
	}
}

func TestTheAllowedPathsAreTheOnesTheDocumentNames(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "..", document))
	if err != nil {
		t.Fatal(err)
	}
	paths := documented(doc)
	if len(paths) == 0 {
		t.Fatalf("%s names no allowed path, so this compared nothing", document)
	}
	for _, apart := range disagreements(allowed, paths) {
		t.Error(apart)
	}
}

func TestAPathInOneListAndNotTheOtherIsReportedBothWays(t *testing.T) {
	doc := []byte("| Rule | Reason |\n|---|---|\n" +
		"| The allowed paths are `internal/database/` and `internal/dbtest/` | x |\n" +
		"| Elsewhere `internal/finding/` is named and is no path | |\n")
	paths := documented(doc)
	if !slices.Equal(paths, []string{"internal/database/", "internal/dbtest/"}) {
		t.Fatalf("read %q from the row, want its two code spans alone", paths)
	}
	if got := disagreements([]string{"internal/database/", "internal/dbtest/"}, paths); got != nil {
		t.Errorf("two lists that agree: %q, want nothing", got)
	}
	got := disagreements([]string{"internal/database/", "internal/finding/"}, paths)
	if len(got) != 2 ||
		!strings.Contains(got[0], "internal/finding/ is allowed here and not named") ||
		!strings.Contains(got[1], "internal/dbtest/ is named in the document and not allowed") {
		t.Errorf("one path each way: %q, want both reported", got)
	}
}

func TestAFileOutsideTheAllowedPathsIsReportedAndOneInsideIsNot(t *testing.T) {
	text := []byte("package finding\n\n// sqlite.Error is named in a comment\n" +
		"func f(err error) {\n\tvar lite *sqlite.Error\n\t_ = errors.As(err, &lite)\n}\n")
	got := violations("internal/finding/x.go", text)
	if len(got) != 1 || !strings.HasPrefix(got[0], "internal/finding/x.go:5:") {
		t.Errorf("outside the allowed paths, got %q, want the one line of code", got)
	}
	if got := violations("internal/database/x.go", text); got != nil {
		t.Errorf("inside the database package, got %q, want nothing", got)
	}
}

func TestAnEngineConstantIsReadUnderAnyImportName(t *testing.T) {
	text := []byte("package finding\n\nimport db \"" + databasePackage + "\"\n\n" +
		"func f(e db.Engine) bool {\n\treturn e == db.Postgres\n}\n")
	got := violations("internal/finding/x.go", text)
	if len(got) != 1 || !strings.HasPrefix(got[0], "internal/finding/x.go:6: db.Postgres") {
		t.Errorf("an aliased constant: got %q, want the one line naming it", got)
	}
	plain := []byte("package finding\n\nfunc f() int {\n\treturn db.Rows\n}\n")
	if got := violations("internal/finding/x.go", plain); got != nil {
		t.Errorf("a selector on another name: got %q, want nothing", got)
	}
}

func TestAOneEngineClosureIsLetPastAndSQLBesideASelectingCallIsRead(t *testing.T) {
	inside := []byte("package schema\n\nfunc TestX(t *testing.T) {\n" +
		"\tdbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {\n" +
		"\t\t_, _ = db.QueryContext(ctx, `SELECT name FROM sqlite_master`)\n" +
		"\t})\n}\n")
	if got := violations("internal/schema/x_test.go", inside); got != nil {
		t.Errorf("SQL inside a closure for one engine: got %q, want nothing", got)
	}
	beside := []byte("package schema\n\nfunc TestX(t *testing.T) {\n" +
		"\tq := `INSERT INTO t ON CONFLICT DO NOTHING`; dbtest.Each(t, database.SQLite, fn)\n}\n")
	got := violations("internal/schema/x_test.go", beside)
	if len(got) != 1 || !strings.HasSuffix(got[0], "ON CONFLICT") {
		t.Errorf("SQL beside a harness call outside its closure: got %q, want it reported", got)
	}
}
