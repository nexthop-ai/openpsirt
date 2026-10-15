// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// This gate reads the names a query writes and the names a migration
// declares. Its consumer is an exit code, so a detection that stopped seeing
// anything reads exactly like a tree with nothing wrong in it.

func TestCommentsAreNotReadAsSQL(t *testing.T) {
	// The comments beside a schema are the reason the schema is legible, and
	// they are full of the words an engine reserves, none of which is an
	// identifier.
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
	// The alias pattern cannot see a table at all — a table is declared
	// rather than invented — so the table pass reads every literal for one.
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
	// A clause assembled a line before it is handed over is read too:
	// literal() reads what is written at the call and returns nothing for a
	// variable.
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
	pieces := assembled(fn, map[token.Pos]bool{}, nil)
	if got := pieces["where"]; !strings.Contains(got, "FROM finding") ||
		!strings.Contains(got, "FROM component") {
		t.Errorf("a variable built in two statements read as %q", got)
	}
	if got := pieces["parts"]; !strings.Contains(got, "JOIN target") {
		t.Errorf("a slice appended to read as %q", got)
	}

	// A piece already read where it was written is not read again, so one
	// defect is reported once rather than at both lines.
	assign, ok := fn.Body.List[0].(*ast.AssignStmt)
	if !ok {
		t.Fatal("the fixture's first statement is not an assignment")
	}
	written := assign.Rhs[0].Pos()
	if got := assembled(fn, map[token.Pos]bool{written: true}, nil)["where"]; strings.Contains(got, "FROM finding") {
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
	// repository. The marker is a quoted table, which appears in a query and
	// not in a sentence.
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

func TestTheColumnsAMigrationDeclaresAreRead(t *testing.T) {
	// A definition's type is concatenated in from the engine's spelling, so
	// the literal holding a column's name ends after it. A quoted name inside
	// an index or a constraint is a reference rather than a declaration.
	const source = "package migrations\n\nfunc tables(t *types) []string {\n" +
		"\treturn []string{\n" +
		"\t\t`CREATE TABLE \"widget\" (\n\t\t\t\"id\"   ` + t.id + `,\n" +
		"\t\t\t-- \"commented\" is prose\n" +
		"\t\t\t\"size_bytes\" ` + t.count + ` NOT NULL,\n" +
		"\t\t\tCONSTRAINT \"widget_fk\" FOREIGN KEY (\"owner_id\") REFERENCES \"person\"(\"id\")\n\t\t)`,\n" +
		"\t\t`CREATE INDEX \"widget_by\" ON \"widget\" (\"made_at\", \"size_bytes\")`,\n" +
		"\t\t`ALTER TABLE \"widget\" ADD COLUMN \"colour\" TEXT NULL`,\n" +
		"\t}\n}\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "internal/database/migrate/migrations/widget.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	columns := map[string]bool{}
	columnsDeclared("internal/database/migrate/migrations/widget.go", file, columns)
	for _, want := range []string{"id", "size_bytes", "colour"} {
		if !columns[want] {
			t.Errorf("%q was not read as a declared column: %v", want, columns)
		}
	}
	for _, not := range []string{"commented", "owner_id", "made_at", "widget", "person"} {
		if columns[not] {
			t.Errorf("%q was read as a declared column", not)
		}
	}

	elsewhere := map[string]bool{}
	columnsDeclared("internal/widget/widget.go", file, elsewhere)
	columnsDeclared("internal/database/migrate/migrations/widget_test.go", file, elsewhere)
	if len(elsewhere) != 0 {
		t.Errorf("a file that is not a migration declared %v", elsewhere)
	}
}

func TestADeclaredColumnIsReportedOnlyWhereItIsWrittenBare(t *testing.T) {
	columns := map[string]bool{
		"id": true, "name": true, "vulnerability_id": true, "by": true, "text": true, "count": true,
	}
	for _, c := range []struct {
		what string
		text string
		want []string
	}{
		{"a bare column", `id = ?`, []string{`"id"`}},
		{"a column qualified by a bare alias", `f.vulnerability_id = ?`, []string{`"f"."vulnerability_id"`}},
		{"a column qualified by a quoted alias", `"f".id = ?`, []string{`"f"."id"`}},
		{"a column qualified by the model's alias", `?TableAlias.id = ?`, []string{`?TableAlias."id"`}},
		{"a column whose qualifier the code supplies", `.id = ?`, []string{`"id"`}},
		{"several in one clause", `name = ? AND f.id <> ?`, []string{`"name"`, `"f"."id"`}},
		{"a column inside a function's arguments", `lower(name) = ?`, []string{`"name"`}},
		{"a quoted column", `"id" = ?`, nil},
		{"a quoted qualified column", `"f"."id" = ?`, nil},
		{"a string constant", `"name" = 'id'`, nil},
		{"a backquoted name", "`id` = ?", nil},
		{"a keyword in capitals", `ORDER BY "id"`, nil},
		{"a function of a column's name", `count(*) AS "n"`, nil},
		{"a cast", `"id"::text`, nil},
		{"a word nothing declares", `ledger = ?`, nil},
		{"a qualifier", `name.x = ?`, nil},
		{"a number running into a word", `1e5 = ?`, nil},
	} {
		var got []string
		for _, one := range bareColumns(c.text, columns) {
			got = append(got, one.quoted())
		}
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s: reported %v, want %v", c.what, got, c.want)
		}
	}
}

func TestColumnsAreReadInTheQueryAndNotInItsValues(t *testing.T) {
	const source = `package x

import "strings"

const listed = "SELECT id FROM \"finding\""

func q(parts []string) {
	db.Where("name = ?", "name")
	db.ExecContext(ctx, "UPDATE \"finding\" SET \"name\" = ? WHERE id = ?", "id", 1)
	db.NewRaw(listed)
	parts = append(parts, "the name")
	strings.Join(parts, "\n")
	query.Set("name", "id")
	db.Set("name = ?", "id")
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "internal/x/x.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	columns := map[string]bool{"id": true, "name": true}
	bad, examined, _ := checkFile(fset, "internal/x/x.go", file, map[string]bool{"finding": true}, columns, nil, nil)
	var got []string
	for _, one := range ordered(bad) {
		got = append(got, fmt.Sprintf("%d:%s", one.line, one.column))
	}
	want := []string{`5:"id"`, `8:"name"`, `9:"id"`, `14:"name"`}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("reported %v, want %v", got, want)
	}
	if examined == 0 {
		t.Error("the queries were not counted as read")
	}
}

func TestAColumnTheBuilderQuotesIsNotReadInAnAssembledQuery(t *testing.T) {
	// The builder quotes what Column and Order are given, so quoting it in
	// the literal as well quotes it twice. One variable holding a subquery
	// and then a clause is read as both.
	const source = `package x

func q() {
	where := db.NewSelect().TableExpr("\"component\" AS \"c\"").Column("c.id").Order("name")
	db.Where("? IS NOT NULL", where)
	where = "c.purl = ?"
	db.Where(where)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "internal/x/x.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	columns := map[string]bool{"id": true, "name": true, "purl": true}
	bad, _, _ := checkFile(fset, "internal/x/x.go", file, map[string]bool{"component": true}, columns, nil, nil)
	var got []string
	for _, one := range ordered(bad) {
		got = append(got, one.column)
	}
	if strings.Join(got, " ") != `"c"."purl"` {
		t.Errorf("reported %v, want only the column in the clause", got)
	}
}

func TestAQualifiedColumnInAFragmentIsReadWhereverItIsHeld(t *testing.T) {
	const source = `package x

import "strings"

const keyMatches = "(cl.outcome = 'mismatched' OR de.live_key IS NULL)"

type On string

const OnStream On = "st.product_id"

const RoutingBatch = "routing.batch"

var allowed = map[string]bool{"q.visibility": true}

type key struct{ expr string }

var keys = []key{{expr: "f.target_id"}}

func product() string { return "tg.stream_id" }

func q() {
	db.Where(HeldAs("f.vulnerability_id"))
	db.Column("c.id").Order("tpl.told_id ASC")
	_ = strings.Contains(body, "setting.kind")
	_ = errorf("set publisher.name, or publisher.namespace in a file")
	_ = []string{"-c", "user.name=test"}
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "internal/x/x.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	columns := map[string]bool{
		"outcome": true, "live_key": true, "product_id": true, "batch": true, "visibility": true,
		"target_id": true, "stream_id": true, "vulnerability_id": true, "id": true, "told_id": true,
		"kind": true, "name": true, "namespace": true,
	}
	bad, _, _ := checkFile(fset, "internal/x/x.go", file, map[string]bool{}, columns, nil, nil)
	var got []string
	for _, one := range ordered(bad) {
		got = append(got, one.column)
	}
	want := `"de"."live_key" "cl"."outcome" "st"."product_id" "f"."target_id" "tg"."stream_id" "f"."vulnerability_id"`
	if strings.Join(got, " ") != want {
		t.Errorf("reported %v, want %s", got, want)
	}

	// A test hands a detector the bare spellings it exists to find.
	file, err = parser.ParseFile(fset, "internal/x/x_test.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if bad, _, _ := checkFile(fset, "internal/x/x_test.go", file, map[string]bool{}, columns, nil, nil); len(bad) != 0 {
		t.Errorf("a test was read for the qualified form: %v", bad)
	}
}

func TestAnInventedNameALikeAndAListAreReadForTheQualifiedForm(t *testing.T) {
	const source = "package x\n\nfunc q() {\n" +
		"\tdb.ColumnExpr(`SUM(\"g\".\"open\") AS \"still_open\"`)\n" +
		"\tdb.Having(`\"g\".\"covered\" = grouped.still_open`)\n" +
		"\tdb.Where(names(\"c.name_folded LIKE ?\"))\n" +
		"\tdb.GroupExpr(names(\"f.id, f.kind\"))\n" +
		"}\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "internal/x/x.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	columns := map[string]bool{"open": true, "covered": true, "name_folded": true, "id": true, "kind": true}
	bad, _, qualified := checkFile(fset, "internal/x/x.go", file, map[string]bool{}, columns, nil, nil)
	var got []string
	for _, one := range ordered(bad) {
		got = append(got, one.column)
	}
	want := `"grouped"."still_open" "c"."name_folded" "f"."id" "f"."kind"`
	if strings.Join(got, " ") != want {
		t.Errorf("reported %v, want %s", got, want)
	}
	if qualified == 0 {
		t.Error("the qualified pass counted nothing it read")
	}
}
