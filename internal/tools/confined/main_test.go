package main

import (
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

		{"ordinary go", "\tfor _, row := range rows {", false},
		{"a portable query", "\tdb.NewSelect().Model(&x).Where(\"id = ?\", id)", false},
		{"a word that merely contains one", "\t// the postgresql documentation", false},
	} {
		if got := asking.MatchString(c.line); got != c.want {
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

func TestWhereAnEngineMayBeNamedIsTheListTheDocumentHolds(t *testing.T) {
	// DESIGN-database.md holds the same list in prose, and two copies is the
	// thing this program exists to catch — so the list is checked for saying
	// something rather than for being exactly what somebody last typed.
	if len(allowed) == 0 {
		t.Fatal("nowhere is allowed to name an engine, so every file would be reported")
	}
	for _, where := range allowed {
		if !strings.HasSuffix(where, "/") && !strings.HasSuffix(where, ".go") {
			t.Errorf("%q is neither a directory nor a file, so it matches by accident", where)
		}
	}
	// The database package is the rule's whole point, and this program has to
	// be exempt or it reports every pattern it looks for.
	for _, want := range []string{"internal/database/", "internal/tools/confined/"} {
		found := false
		for _, where := range allowed {
			if where == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not allowed to name an engine", want)
		}
	}
}
