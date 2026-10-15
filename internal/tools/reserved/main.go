// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command reserved reports SQL identifiers this code writes bare.
//
// Queries here are written once and run against four engines, and a name this
// code makes up — an alias on a subquery, a column an expression is given so a
// later clause can refer to it — is not checked by anything until one of them
// refuses to parse it. The four do not reserve the same words: `groups` is
// reserved by PostgreSQL and not by MySQL, `usage` by MySQL and not by
// PostgreSQL, and the day somebody writes `AS usage` the suite is green on
// three engines and a production deployment on the fourth stops answering.
//
// A name a query writes is reported for being bare rather than for being
// reserved. Checking a word against the list the engines reserve is a weaker
// property than the rule, which is that every identifier is quoted, and the
// list goes stale the first time an engine reserves a word: MySQL 8.0 added
// `rank`, `groups`, `lead` and `cume_dist`. A quoted name does not match at
// all, so a hit is by construction an unquoted name and the fix is one pair of
// quotes.
//
// | Pass | Reads | Reports |
// |---|---|---|
// | Invented names | `AS <word>` in a statement or a builder argument | an alias or an output name written bare |
// | Tables | a table after FROM, JOIN, INTO or UPDATE, or opening a table expression | a table the migrations declare, written bare |
// | Declared columns | a statement, the SQL argument of a builder method, and a clause built in a variable and handed to one | a column the migrations declare, written bare, alone or after a qualifier |
// | Qualified columns | every literal outside the tests and the migrations: a clause, or one qualified name handed to code that places it | a column the migrations declare, or a name the file's queries invent with AS, written bare after a qualifier |
// | Definitions | the migrations' data-definition literals | a declared name that collides with a word an engine reserves |
// | Model aliases | a struct tag's alias | an alias that collides with a word an engine reserves |
//
// A name that is not in a literal stays invisible to it. An alias
// assembled from two pieces — `"… AS " + state.alias` — is invisible to
// anything reading source as text, and there is no parser here for four
// dialects. That is the safe direction for a check that fails a build, and it
// is why the all-clear says "in a literal" rather than claiming the rule
// outright. The schema test that reads the live database is the other half.
//
// The data-definition half below is the other way round and stays that way.
// Those names are declared rather than invented, the migrations are where they
// are declared, and the question there is whether a declared name collides
// with a reserved word — which is what the list is for.
//
// A declared column is recognized by name: the migrations declare every
// column this schema has, and a lower-case word in a query that names one is
// that column. Keywords are written in capitals here, which is what keeps
// `ORDER BY` from reading as a column called "by". A word followed by a
// parenthesis is a function, a word followed by a dot is a qualifier, and the
// arguments after a builder method's SQL are values, which are free to be a
// word the schema has a column of.
//
// Deliberately crude, like the two gates beside it: it reads the source as
// text rather than parsing SQL, because SQL is what is inside the strings and
// there is no parser here for four dialects of it. It errs toward saying
// nothing — an alias built by concatenation is invisible to it — which is the
// right direction for a check that fails a build.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// invented matches a name this code makes up: AS, then a bare word. A quoted
// one does not match, which is what makes every hit a defect and the fix one
// pair of quotes.
var invented = regexp.MustCompile(`(?i)\bAS\s+([A-Za-z_][A-Za-z0-9_]*)\b`)

// statement recognizes a string literal as SQL wherever it is written.
//
// A query held in a const, returned by a helper, or handed to the raw-query
// constructor is read as well as the arguments of the builder's own methods.
// A query's home is not what makes it a query.
//
// `FROM "` or `JOIN "` is the marker because every table in this schema is
// quoted, so it appears in SQL and not in prose. The bare keywords match
// English: an API description saying "as a" after the word "from" is not an
// alias.
var statement = regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+"`)

// declared matches a bare schema identifier in data-definition language.
//
// The existence clause is stepped over rather than read as a name: "DROP TABLE
// IF EXISTS" declares nothing called "if", and reporting one is how a check
// that reads text rather than parsing it goes wrong.
//
// Only inside the migrations, where every string is DDL by construction,
// so the false positives that keep this check narrow elsewhere cannot arise.
// The alias pattern above cannot see these at all — a `DROP TABLE` names no
// alias and contains no AS — so a table renamed to something one engine
// reserves passed the gate that exists to catch exactly that.
var declared = regexp.MustCompile(
	`(?i)\b(?:TABLE|INDEX|COLUMN|CONSTRAINT|REFERENCES)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)\b`)

// clause is the words that stand between one of those keywords and the name,
// which are grammar rather than identifiers: "DROP TABLE IF EXISTS x" declares
// nothing called "if".
var clause = map[string]bool{"if": true, "not": true, "exists": true}

// creating matches a table the migrations declare, quoted as they all are.
//
// Read so that the check below can tell a schema name from a keyword without
// a list of keywords somebody typed: what this schema calls its tables is what
// the migrations made, and nothing else needs recognizing.
var creating = regexp.MustCompile(`(?i)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"([A-Za-z_][A-Za-z0-9_]*)"`)

// named matches a table a query names, quoted or bare — after FROM, JOIN,
// INTO or UPDATE, or opening a table expression that goes on to alias it.
//
// The alias pattern above sees only the names a query invents. A table is
// declared rather than invented, and a table whose name an engine reserves,
// written bare, is refused by that engine alone.
var named = regexp.MustCompile(`(?i)\b(?:FROM|JOIN|INTO|UPDATE)\s+("?)([A-Za-z_][A-Za-z0-9_]*)`)

// opening matches a table expression, which names its table and then aliases
// it. The alias is what tells it from a condition: a literal beginning with a
// word this schema has a table of is otherwise a column of that name or a
// qualified one.
var opening = regexp.MustCompile(`(?i)\A\s*("?)([A-Za-z_][A-Za-z0-9_]*)"?\s+AS\b`)

// alone matches a literal that is a table name and nothing else.
//
// Only ever applied to an argument of a method that names a table, because a
// literal that is one bare word is a constant nearly everywhere else: "person"
// is a kind of subject in three packages before it is a table.
var alone = regexp.MustCompile(`\A\s*("?)([A-Za-z_][A-Za-z0-9_]*)"?\s*\z`)

// naming is the builder's methods whose argument is a table rather than a
// clause, which is what makes a bare word in one of them an identifier.
var naming = map[string]bool{"TableExpr": true, "Table": true, "ModelTableExpr": true}

// aliased matches the table alias a model declares in its struct tag.
//
// Read because a tag is where an alias is written for most of this codebase's
// queries, and the walk below sees only call arguments. A reserved alias in a
// tag works only because the library quotes what a tag declares — a property
// of the library rather than of this code — and the first raw expression
// naming that alias is a syntax error on every engine reserving it.
var aliased = regexp.MustCompile(`\balias:([A-Za-z_][A-Za-z0-9_]*)`)

// writing is the query builder's methods that take SQL as text.
//
// Matched by name rather than by resolving the type, which is the same
// crudeness the two gates beside this one accept: something else with a method
// called Where is read as SQL and reports a word it should not. That direction
// is the safe one — it can only ask somebody to rename a thing — and the
// alternative is a type checker in a program whose whole job is to grep.
//
// Naming them is what keeps prose out. Nearly every English sentence in this
// repository contains the word "as", and a doc comment is not SQL.
var writing = map[string]bool{
	"TableExpr": true, "ColumnExpr": true, "GroupExpr": true, "OrderExpr": true,
	"Having": true, "Where": true, "Join": true, "JoinOn": true,
	"WhereOr": true, "Raw": true, "NewRaw": true, "NewRawQuery": true, "Exec": true,
	"ExecContext": true, "QueryContext": true, "Set": true,
}

// found is one place a name was written wrongly.
type found struct {
	word string
	file string
	line int
	// bare says the name is unquoted, which is the whole complaint. Without
	// it the complaint is that a declared name collides with a reserved word.
	bare bool
	// table says the name is one the schema declares rather than one the
	// query invents, which is a different sentence to fix it by.
	table bool
	// column is a declared column written bare, as it reads quoted, and
	// empty for every other finding.
	column string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "generate" {
		if err := generate(); err != nil {
			fmt.Fprintln(os.Stderr, "reserved-words:", err)
			os.Exit(1)
		}
		return
	}

	reserved := map[string]bool{}
	for _, word := range reservedWords() {
		reserved[word] = true
	}

	// The tables and columns the migrations made, read first, because the
	// check below tells a schema name from a keyword by asking whether this
	// schema has one of that name.
	schema := map[string]bool{}
	columns := map[string]bool{}
	// The names the code that runs invents with AS, read before any file is
	// checked, because a derived table built in one file is read in another.
	invented := map[string]bool{}
	fset := token.NewFileSet()
	_, err := walk.Only(".go", []string{"web"}, func(path string, body []byte) error {
		tablesDeclared(path, body, schema)
		if !strings.Contains(path, "database/migrate/migrations/") {
			if strings.HasSuffix(path, "_test.go") || strings.Contains(path, "internal/tools/reserved") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, body, 0)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			for word := range inventedNames(file, nil) {
				invented[word] = true
			}
			return nil
		}
		file, err := parser.ParseFile(fset, path, body, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		columnsDeclared(path, file, columns)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(schema) == 0 {
		fmt.Fprintln(os.Stderr, "the migrations declare no tables, so the table pass would check nothing")
		os.Exit(2)
	}
	if len(columns) == 0 {
		fmt.Fprintln(os.Stderr, "the migrations declare no columns, so the column pass would check nothing")
		os.Exit(2)
	}

	var bad []found
	queries, qualified := 0, 0
	// web holds the interface, which writes no SQL: it asks this server.
	read, err := walk.Only(".go", []string{"web"}, func(path string, _ []byte) error {
		// This checker's own tests are written out of what it reports: a bare
		// table in a fixture is the input, not a defect. One directory rather
		// than a pattern, so nothing else inherits the exemption.
		if strings.Contains(path, "internal/tools/reserved") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		hits, examined, read := checkFile(fset, path, file, schema, columns, reserved, invented)
		bad = append(bad, hits...)
		queries += examined
		qualified += read
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if queries == 0 {
		fmt.Fprintln(os.Stderr, "no query was read, so the column pass checked nothing")
		os.Exit(2)
	}
	if qualified == 0 {
		fmt.Fprintln(os.Stderr, "no literal of the code that runs was read, so the qualified pass checked nothing")
		os.Exit(2)
	}

	if len(bad) == 0 {
		fmt.Printf("every name a query invents in a literal is quoted, every table "+
			"and declared column one names is quoted, and no name a migration "+
			"declares collides with a word any of the four engines reserves (%d words "+
			"checked over %d files, %d tables, %d columns, %d queries)\n",
			len(reservedWords()), read, len(schema), len(columns), queries)
		return
	}
	for _, one := range ordered(bad) {
		if one.column != "" {
			fmt.Fprintf(os.Stderr, "%s:%d: the column %q is written bare. "+
				"Quote it: %s\n", one.file, one.line, one.word, one.column)
			continue
		}
		if one.table {
			fmt.Fprintf(os.Stderr, "%s:%d: the table %q is named bare. "+
				"Quote it: %q\n", one.file, one.line, one.word, one.word)
			continue
		}
		if one.bare {
			fmt.Fprintf(os.Stderr, "%s:%d: the name %q is written bare. "+
				"Quote it: AS %q\n", one.file, one.line, one.word, one.word)
			continue
		}
		fmt.Fprintf(os.Stderr, "%s:%d: %q is reserved by one of the four engines. "+
			"Quote it, or call it something else\n", one.file, one.line, one.word)
	}
	fmt.Fprintf(os.Stderr, "\n%d name(s) an engine may refuse to parse.\n", len(ordered(bad)))
	os.Exit(1)
}

// assembledFrom names the variable a clause was built in, where the argument
// is one: the variable itself, or the slice a join reads.
func assembledFrom(arg ast.Expr) string {
	switch typed := arg.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.CallExpr:
		// strings.Join(pieces, " OR ") and anything shaped like it: what the
		// engine sees is every piece, so every piece is what to read.
		if len(typed.Args) == 0 {
			return ""
		}
		if inner, ok := typed.Args[0].(*ast.Ident); ok {
			return inner.Name
		}
	}
	return ""
}

// assembled gathers, per variable, every string literal a function puts in it.
//
// Deliberately more than any one run would produce: a variable assigned in one
// arm and appended to in another yields both here, and the engine sees one of
// them. Reading too much can only report a name that is written somewhere in
// this function, which is a name somebody wrote bare either way — and reading
// too little is what left three assembled clauses unread.
//
// Everything the statement pass has already read is left out, so a clause
// written whole and then handed over as a variable is one defect and not two.
//
// A call to a method named in quoting is not read: the builder quotes its
// argument itself.
func assembled(fn *ast.FuncDecl, seen map[token.Pos]bool, quoting map[string]bool) map[string]string {
	pieces := map[string]string{}
	keep := func(name string, from ast.Expr) {
		if name == "" || from == nil {
			return
		}
		ast.Inspect(from, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if method, ok := call.Fun.(*ast.SelectorExpr); ok && quoting[method.Sel.Name] {
					return false
				}
			}
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			// Already read where it is written, as a statement in its own
			// right. Reading it again here would name one defect twice, at
			// the line it was written and at the line it was handed over.
			if seen[lit.Pos()] {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				text = lit.Value
			}
			pieces[name] += " " + text
			return true
		})
	}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.AssignStmt:
			for i, target := range typed.Lhs {
				ident, ok := target.(*ast.Ident)
				if !ok || i >= len(typed.Rhs) {
					continue
				}
				keep(ident.Name, typed.Rhs[i])
			}
		case *ast.ValueSpec:
			for i, ident := range typed.Names {
				if i < len(typed.Values) {
					keep(ident.Name, typed.Values[i])
				}
			}
		case *ast.CallExpr:
			// append(pieces, "…"), which is how a list of conditions is built.
			if ident, ok := typed.Fun.(*ast.Ident); ok && ident.Name == "append" && len(typed.Args) > 1 {
				if into, ok := typed.Args[0].(*ast.Ident); ok {
					for _, arg := range typed.Args[1:] {
						keep(into.Name, arg)
					}
				}
			}
		}
		return true
	})
	return pieces
}

// unquotedTables reports every table of this schema that the text names bare.
//
// Quoted or bare is the whole question: a quoted name is safe on all four
// engines whatever any of them reserves, and a bare one is safe until somebody
// renames the table or an engine adds a keyword. A word this schema has no
// table of is not a table — which is how a clause keyword is told from a name
// without a list of keywords somebody typed and nothing refreshes.
func unquotedTables(text string, schema map[string]bool, path string, line int) []found {
	var bare []found
	for _, one := range bareTables(text, schema) {
		bare = append(bare, found{word: one.word, file: path, line: line, table: true, bare: true})
	}
	return bare
}

// A bareTable is a table of this schema written bare, and the span of the
// clause naming it.
type bareTable struct {
	word       string
	start, end int
}

func bareTables(text string, schema map[string]bool) []bareTable {
	var bare []bareTable
	matches := named.FindAllStringSubmatchIndex(text, -1)
	if match := opening.FindStringSubmatchIndex(text); match != nil {
		matches = append(matches, match)
	}
	for _, match := range matches {
		word := strings.ToLower(text[match[4]:match[5]])
		if text[match[2]:match[3]] == `"` || !schema[word] {
			continue
		}
		bare = append(bare, bareTable{word: word, start: match[0], end: match[1]})
	}
	return bare
}

// withoutSQLComments drops what a migration says about its own columns.
//
// The comments beside a schema are the reason the schema is legible, and they
// are full of the words an engine reserves — "the table exists", "on and
// over" — none of which is an identifier.
func withoutSQLComments(text string) string {
	var kept strings.Builder
	for line := range strings.SplitSeq(text, "\n") {
		if cut := strings.Index(line, "--"); cut >= 0 {
			line = line[:cut]
		}
		kept.WriteString(line)
		kept.WriteString("\n")
	}
	return kept.String()
}

// literal reads a string argument, following the concatenations these queries
// are written as: a clause built from three pieces on three lines is one
// string to the engine and has to be one string here.
func literal(fset *token.FileSet, node ast.Expr) (string, int, bool) {
	parts := piecesOf(fset, node)
	if len(parts) == 0 {
		return "", 0, false
	}
	return joined(parts), parts[0].line, true
}
