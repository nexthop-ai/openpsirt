// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command confined reports engine-specific code outside where it is allowed.
//
// Queries are written once and run against four engines. The places that have
// to ask an engine directly are the rows of `design-docs/database.md`
// § Engine-specific code, and this program reads for a dialect being named
// (the engine constants, an engine compared by value or name, the driver error
// types, and the SQL each engine spells its own way) and refuses any file
// outside the allowed paths. It also refuses an allowed path the document does
// not name, and the reverse.
//
// It reads text and errs toward reporting, so a new place is added to the list
// deliberately.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// asking is a line naming an engine, a driver's own error type, or SQL only
// some of them accept. The engine constants are matched separately, through
// whatever name the file imports the database package under.
var asking = regexp.MustCompile(
	`(mysql\.MySQLError|pgconn\.PgError|sqlite\.Error|` +
		// bun's own names for the engines, which a branch on the handle's
		// dialect compares against.
		`dialect\.(?:PG|MySQL|SQLite|MSSQL)\b|` +
		// The handle is asked which engine it is, which is how a branch is
		// written without naming a constant.
		`Dialect\(\)\.Name|` +
		// An engine compared as a value or as its name. The engine type is a
		// string, so a literal compares directly and names no constant. A
		// value is matched by a name ending in engine, a field's or a local's.
		`(?i:engine)\s*[!=]=|` +
		`[!=]=\s*"(?:postgres|mysql|mariadb|sqlite)"|` +
		`"(?:postgres|mysql|mariadb|sqlite)"\s*[!=]=|` +
		`\bcase\b[^:]*"(?:postgres|mysql|mariadb|sqlite)"|` +
		// And bun's own spellings of the two upsert idioms, which are the same
		// branch written through the query builder rather than as SQL.
		`\.Ignore\(\)|` +
		`ON CONFLICT|ON DUPLICATE KEY|INSERT IGNORE|ILIKE|julianday|` +
		`TIMESTAMPDIFF|EXTRACT\(EPOCH|FOR UPDATE|pg_advisory|GET_LOCK|` +
		// MySQL has no RETURNING; an empty Returning("") asks for none.
		`\bRETURNING\b|\.Returning\("[^"]|` +
		`STRING_AGG|GROUP_CONCAT|LAST_INSERT_ID|unnest\(|\bANALYZE\b|` +
		// Each engine's own catalog.
		`information_schema|pg_catalog|sqlite_master|` +
		// PostgreSQL's cast operator.
		`::(?:timestamptz|timestamp|text|int|bigint|integer|date|numeric|jsonb|json|interval|regclass|boolean|bool)\b)`)

// databasePackage is the import path whose constants name the engines.
const databasePackage = "github.com/nexthop-ai/openpsirt/internal/database"

// engineConstant is the pattern for an engine constant named through the
// name a file imports the database package under.
func engineConstant(name string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\.(?:Postgres|MySQL|MariaDB|SQLite)\b`)
}

// asks is what in one line asks an engine directly, or empty. constant is
// the file's engine-constant pattern.
func asks(line string, constant *regexp.Regexp) string {
	if match := constant.FindString(line); match != "" {
		return match
	}
	return asking.FindString(line)
}

// selecting is an engine named to choose which engine a test runs against,
// which the harness exists to do. Anything else naming one is a branch.
var selecting = regexp.MustCompile(`dbtest\.\w+\([^)]*database\.\w+`)

// allowed is where an engine may be named. Each path is a code span in the
// rule row of `design-docs/database.md` § Engine-specific code that names the
// allowed paths, and the reasons are that section's rows; the program refuses
// a path in one and not the other.
var allowed = []string{
	"internal/database/",
	"internal/queue/claim_locking.go",
	"internal/tools/confined/",
	"internal/dbtest/",
	"internal/tools/reserved/",
	"internal/tools/rehearsal/",
}

// shape reads one file for what the line scan cannot see: the name it
// imports the database package under, and the lines inside a test's
// dbtest.Only closure, which run on the one engine the call names.
func shape(path string, text []byte) (name string, only func(line int) bool) {
	name = "database"
	only = func(int) bool { return false }
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, text, parser.SkipObjectResolution)
	if err != nil {
		return name, only
	}
	for _, spec := range file.Imports {
		if strings.Trim(spec.Path.Value, `"`) == databasePackage && spec.Name != nil {
			name = spec.Name.Name
		}
	}
	type span struct{ from, to int }
	var spans []span
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Only" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "dbtest" {
			return true
		}
		spans = append(spans, span{fset.Position(call.Pos()).Line, fset.Position(call.End()).Line})
		return true
	})
	only = func(line int) bool {
		for _, s := range spans {
			if line >= s.from && line <= s.to {
				return true
			}
		}
		return false
	}
	return name, only
}

// violations is every line of one file that asks an engine directly, outside
// where that is allowed. A file on the allowed list has none.
func violations(path string, text []byte) []string {
	for _, where := range allowed {
		if strings.HasPrefix(path, where) {
			return nil
		}
	}
	name, only := shape(path, text)
	constant := engineConstant(name)
	var bad []string
	for i, line := range strings.Split(string(text), "\n") {
		// Comments name engines constantly, and correctly: what is being
		// looked for is code that branches on one.
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Choosing which engine a test runs on is not branching a query on
		// one. `dbtest.Only(t, database.SQLite, …)` says this question has
		// the same answer everywhere and is asked once, and what runs inside
		// it runs on that engine alone. Every line from the call to its closing
		// parenthesis is let past, the closure's included.
		if only(i + 1) {
			continue
		}
		line = selecting.ReplaceAllString(line, "")
		if match := asks(line, constant); match != "" {
			bad = append(bad, fmt.Sprintf("%s:%d: %s", path, i+1, match))
		}
	}
	return bad
}

// rowOpening is the start of the rule row in design-docs/database.md that
// lists the allowed paths.
const rowOpening = "| The allowed paths are "

// documented is every path the design document's allowed-paths row names in
// a code span.
func documented(doc []byte) []string {
	var paths []string
	for _, line := range strings.Split(string(doc), "\n") {
		if !strings.HasPrefix(line, rowOpening) {
			continue
		}
		for _, m := range codeSpan.FindAllStringSubmatch(line, -1) {
			paths = append(paths, m[1])
		}
	}
	return paths
}

var codeSpan = regexp.MustCompile("`([^`]+)`")

// disagreements is every path the program allows and the document does not
// name, and every path the document names and the program does not allow.
func disagreements(allow, doc []string) []string {
	var bad []string
	for _, p := range allow {
		if !slices.Contains(doc, p) {
			bad = append(bad, fmt.Sprintf("%s is allowed here and not named in the document", p))
		}
	}
	for _, p := range doc {
		if !slices.Contains(allow, p) {
			bad = append(bad, fmt.Sprintf("%s is named in the document and not allowed here", p))
		}
	}
	return bad
}

// document holds the allowed paths and the reason for each.
const document = "design-docs/database.md"

func main() {
	doc, err := os.ReadFile(document)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	paths := documented(doc)
	if len(paths) == 0 {
		fmt.Fprintf(os.Stderr, "%s names no allowed path, so nothing was compared\n", document)
		os.Exit(2)
	}
	if apart := disagreements(allowed, paths); len(apart) > 0 {
		for _, one := range apart {
			fmt.Fprintf(os.Stderr, "%s: %s\n", document, one)
		}
		os.Exit(1)
	}
	var bad []string
	// web holds the interface, which reaches no engine at all: it talks to
	// this server over HTTP.
	read, err := walk.Only(".go", []string{"web"}, func(path string, text []byte) error {
		bad = append(bad, violations(path, text)...)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if read == 0 {
		fmt.Fprintln(os.Stderr, "no Go file was read, so this checked nothing")
		os.Exit(2)
	}
	if len(bad) == 0 {
		fmt.Printf("engine-specific code is confined to the %d paths this holds and %s names (%d files)\n",
			len(allowed), document, read)
		return
	}
	sort.Strings(bad)
	for _, one := range bad {
		fmt.Fprintf(os.Stderr, "%s asks an engine directly, outside where that is allowed\n", one)
	}
	fmt.Fprintf(os.Stderr, "\n%d place(s) outside internal/database and the queue's locking. "+
		"Move it there, or widen the list here and in design-docs/database.md together.\n", len(bad))
	os.Exit(1)
}
