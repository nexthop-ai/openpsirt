// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// check runs every pass over one source file.
func check(t *testing.T, path, source string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	schema := map[string]bool{"finding": true, "component": true}
	reserved := map[string]bool{"as": true, "order": true}
	var got []string
	for _, one := range ordered(checkFile(fset, path, file, schema, reserved)) {
		got = append(got, one.word)
	}
	return got
}

func TestANameBesideAStatementOnOneLineIsStillRead(t *testing.T) {
	const source = `package x

func q() {
	db.ColumnExpr("count(*) AS total").Join("JOIN \"component\" AS \"c\" ON \"c\".\"id\" = 1")
	db.NewRaw("SELECT 1 AS sum " + "FROM \"finding\"")
	db.NewRaw("SELECT 1 AS \"fine\" " + "FROM \"finding\"")
}
`
	got := check(t, "internal/x/x.go", source)
	if !slices.Equal(got, []string{"total", "sum"}) {
		t.Errorf("reported %v, want total and sum and nothing quoted", got)
	}
}

func TestEveryPassReportsWhatItIsFor(t *testing.T) {
	for _, c := range []struct {
		what, path, source string
		want               []string
	}{
		{
			"a bare alias in a call", "internal/x/x.go",
			"package x\nfunc q() { db.ColumnExpr(\"1 AS n\") }\n", []string{"n"},
		},
		{
			"a quoted alias in a call", "internal/x/x.go",
			"package x\nfunc q() { db.ColumnExpr(`1 AS \"n\"`) }\n", nil,
		},
		{
			"a reserved alias in a struct tag", "internal/x/x.go",
			"package x\ntype m struct{ B int `bun:\"table:settings,alias:as\"` }\n", []string{"as"},
		},
		{
			"an alias in a struct tag nobody reserves", "internal/x/x.go",
			"package x\ntype m struct{ B int `bun:\"table:settings,alias:st\"` }\n", nil,
		},
		{
			"a reserved word a migration declares", "internal/database/migrate/migrations/x.go",
			"package x\nconst up = `DROP TABLE IF EXISTS order`\n", []string{"order"},
		},
		{
			"a bare table split across two pieces", "internal/x/x.go",
			"package x\nfunc q() { db.Where(\"id IN (SELECT 1 FROM \" + \"finding)\") }\n", []string{"finding"},
		},
		{
			"a bare table inside one piece, reported once", "internal/x/x.go",
			"package x\nfunc q() { db.Where(\"id IN (SELECT 1 FROM finding)\") }\n", []string{"finding"},
		},
	} {
		if got := check(t, c.path, c.source); !slices.Equal(got, c.want) {
			t.Errorf("%s: reported %v, want %v", c.what, got, c.want)
		}
	}
}

func TestTheGeneratedListIsFormattedGoInTheOrderGiven(t *testing.T) {
	words := []string{"all", "and", "as", "between", "by", "case", "group"}
	body, err := renderGenerated(words)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "DO NOT EDIT") || !strings.Contains(text, "// 7 words.") {
		t.Errorf("the generated file does not say what it is:\n%s", text)
	}
	if !strings.Contains(text, "\t\"all\", \"and\", \"as\", \"between\", \"by\", \"case\",\n\t\"group\",\n") {
		t.Errorf("the words are not six to a line in the order given:\n%s", text)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "words_asked.go", body, 0); err != nil {
		t.Errorf("the generated file is not Go: %v", err)
	}
}
