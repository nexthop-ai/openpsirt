// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// This gate reads every name a query invents and checks it against what the
// four engines actually reserve. It had no test, and its consumer is an exit
// code — so a detection that stopped seeing anything would read exactly like a
// tree with nothing wrong in it.

func TestCommentsAreNotReadAsSQL(t *testing.T) {
	// The comments beside a schema are the reason the schema is legible, and
	// they are full of the words an engine reserves. Read as identifiers they
	// reported fifty names, none of which was one.
	for _, c := range []struct {
		what   string
		text   string
		gone   string
		stayed string
	}{
		{
			"a trailing comment", "SELECT 1 -- the table exists\nFROM thing",
			"the table exists", "FROM thing",
		},
		{
			"a whole-line comment", "-- on and over\nSELECT \"order\" FROM thing",
			"on and over", `"order"`,
		},
		{
			"no comment at all", "SELECT 1 FROM thing", "", "FROM thing",
		},
	} {
		got := withoutSQLComments(c.text)
		if c.gone != "" && strings.Contains(got, c.gone) {
			t.Errorf("%s: %q survived stripping: %q", c.what, c.gone, got)
		}
		if !strings.Contains(got, c.stayed) {
			t.Errorf("%s: %q was stripped along with the comment: %q", c.what, c.stayed, got)
		}
	}
}

func TestAConcatenatedClauseIsOneString(t *testing.T) {
	// A clause built from three pieces on three lines is one string to the
	// engine, so it has to be one string here: read piece by piece, a name
	// split across a join is a name this gate cannot see.
	for _, c := range []struct {
		what string
		expr string
		want string
		read bool
	}{
		{"a plain literal", `"SELECT 1"`, "SELECT 1", true},
		{
			"three pieces on one line",
			`"SELECT a " + "FROM t " + "WHERE b = ?"`,
			"SELECT a FROM t WHERE b = ?", true,
		},
		{"a raw string", "`SELECT \"order\" FROM t`", `SELECT "order" FROM t`, true},
		{"a number", `42`, "", false},
		{"something computed", `fmt.Sprintf("SELECT %s", column)`, "", false},
	} {
		fset := token.NewFileSet()
		node, err := parser.ParseExpr(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		got, _, ok := literal(fset, node)
		if ok != c.read {
			t.Errorf("%s: read=%v, want %v", c.what, ok, c.read)
			continue
		}
		if ok && got != c.want {
			t.Errorf("%s: read %q, want %q", c.what, got, c.want)
		}
	}
}

func TestATableIsReportedOnlyWhereItIsWrittenBare(t *testing.T) {
	// Aliases were quoted everywhere and tables were not, in the same clause
	// and often on the same line. The alias pattern cannot see a table at all
	// — a table is declared rather than invented — so nothing outside the
	// migrations looked at one.
	schema := map[string]bool{"finding": true, "component": true}
	for _, c := range []struct {
		what string
		text string
		want []string
	}{
		{"a bare table after FROM", `SELECT 1 FROM finding`, []string{"finding"}},
		{"a bare table after JOIN", `JOIN component AS "c" ON c.id = f.component_id`, []string{"component"}},
		{"a bare table after INTO", `INSERT INTO finding ("id") VALUES (?)`, []string{"finding"}},
		{"a bare table after UPDATE", `UPDATE component SET "name" = ?`, []string{"component"}},
		{"a bare table opening a table expression", `finding AS "f"`, []string{"finding"}},
		{"a quoted table", `SELECT 1 FROM "finding"`, nil},
		{"a quoted table after INTO", `INSERT INTO "finding" ("id") VALUES (?)`, nil},
		{"a quoted table after UPDATE", `UPDATE "component" SET "name" = ?`, nil},
		{"a quoted table opening one", `"finding" AS "f"`, nil},
		{"a column of the same name as a table", `component = ?`, nil},
		{"a qualified column", `finding.id = ?`, nil},
		{"a word this schema has no table of", `SELECT 1 FROM ledger`, nil},
	} {
		var got []string
		for _, one := range unquotedTables(c.text, schema, "x.go", 1) {
			got = append(got, one.word)
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: reported %v, want %v", c.what, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: reported %v, want %v", c.what, got, c.want)
				break
			}
		}
	}
}

func TestAClauseBuiltInAVariableIsRead(t *testing.T) {
	// The three clauses this could not see were assembled a line before they
	// were handed over: literal() reads what is written at the call and
	// returns nothing for a variable, so the fragment nobody had read was
	// exactly the one nothing checked.
	const source = `package x

func q() {
	where := "SELECT 1 FROM finding AS f"
	where += " AND EXISTS (SELECT 1 FROM component)"
	parts := []string{}
	parts = append(parts, "JOIN target AS tg")
	db.Where(where)
	db.Having(strings.Join(parts, " OR "))
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := file.Decls[0].(*ast.FuncDecl)
	if !ok {
		t.Fatal("the fixture's first declaration is not a function")
	}
	pieces := assembled(fset, fn, map[int]bool{})
	if got := pieces["where"]; !strings.Contains(got, "FROM finding") ||
		!strings.Contains(got, "FROM component") {
		t.Errorf("a variable built in two statements read as %q", got)
	}
	if got := pieces["parts"]; !strings.Contains(got, "JOIN target") {
		t.Errorf("a slice appended to read as %q", got)
	}

	// A piece already read where it was written is not read again, so one
	// defect is reported once rather than at both lines.
	written := fset.Position(fn.Body.List[0].Pos()).Line
	if got := assembled(fset, fn, map[int]bool{written: true})["where"]; strings.Contains(got, "FROM finding") {
		t.Errorf("a statement already read was read again: %q", got)
	}

	// And the variable a call is handed is the one to look up.
	for _, c := range []struct{ what, expr, want string }{
		{"a variable", "db.Where(where)", "where"},
		{"a joined slice", `db.Having(strings.Join(parts, " OR "))`, "parts"},
		{"something else entirely", `db.Where("x = ?", 1)`, ""},
	} {
		node, err := parser.ParseExpr(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			t.Fatalf("%s: not a call", c.what)
		}
		if got := assembledFrom(call.Args[0]); got != c.want {
			t.Errorf("%s: read %q, want %q", c.what, got, c.want)
		}
	}
}

func TestWhatIsReadAsAStatementAtAll(t *testing.T) {
	// The alias half is applied only to a literal this recognizes as SQL,
	// because "as" is a word in nearly every English sentence in this
	// repository — a version that read them reported eighteen names, every
	// one of them prose. The marker is a quoted table, which appears in a
	// query and not in a sentence.
	//
	// The table half deliberately does not wait for it: a query whose tables
	// are all bare carries no marker, and that is the query nothing was
	// looking at.
	for _, c := range []struct {
		what string
		text string
		want bool
	}{
		{"a query naming a quoted table", `SELECT 1 FROM "finding" AS f`, true},
		{"a join onto a quoted table", `JOIN "component" AS c ON c.id = f.id`, true},
		{"a query whose tables are bare", `SELECT id FROM job WHERE kind = ?`, false},
		{"a sentence using the word from", `read from the document as it arrived`, false},
		{"a sentence about a table", `the index's table reads as %q`, false},
	} {
		if got := statement.MatchString(c.text); got != c.want {
			t.Errorf("%s: read as a statement=%v, want %v", c.what, got, c.want)
		}
	}
}
