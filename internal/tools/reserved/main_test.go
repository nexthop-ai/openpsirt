package main

import (
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
