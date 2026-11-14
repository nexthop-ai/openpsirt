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
	"path/filepath"
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
		// branch written through the query builder.
		`\.Ignore\(\)|\.On\("(?:CONFLICT|DUPLICATE KEY)|` +
		`ON CONFLICT|ON DUPLICATE KEY|INSERT IGNORE|ILIKE|julianday|` +
		`TIMESTAMPDIFF|EXTRACT\(EPOCH|FOR UPDATE|pg_advisory|GET_LOCK|` +
		// MySQL has no RETURNING; an empty Returning("") asks for none.
		`\bRETURNING\b|\.Returning\("[^"]|` +
		`STRING_AGG|GROUP_CONCAT|LAST_INSERT_ID|unnest\(|\bANALYZE\b|` +
		// Each engine's own catalog, statistics, functions and settings:
		// PostgreSQL's pg_ names, MySQL's and MariaDB's schemas and session
		// variables, SQLite's sqlite_ tables and pragmas.
		`information_schema|performance_schema|\bpg_[a-z_]+|\binnodb_\w+|\bsqlite_\w+|` +
		`\bPRAGMA\b|\bpragma_\w+|@@\w+|` +
		// PostgreSQL's cast operator.
		`::(?:timestamptz|timestamp|text|int|bigint|integer|smallint|date|numeric|jsonb|json|interval|` +
		`regclass|boolean|bool|float\d*|real|double|varchar|uuid)\b)`)

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

// parsed is one file of a package, read for what the line scan cannot see.
type parsed struct {
	path string
	text []byte
	// name is what the file imports the database package under.
	name string
	fset *token.FileSet
	file *ast.File
}

// lines is the lines from one node's start to its end.
type lines struct{ from, to int }

func (l lines) holds(line int) bool { return line >= l.from && line <= l.to }

func spanOf(fset *token.FileSet, node ast.Node) lines {
	return lines{fset.Position(node.Pos()).Line, fset.Position(node.End()).Line}
}

// parse reads one file's import name for the database package and its
// syntax. A file that does not parse keeps the default name and no syntax.
func parse(path string, text []byte) parsed {
	p := parsed{path: path, text: text, name: "database", fset: token.NewFileSet()}
	file, err := parser.ParseFile(p.fset, path, text, parser.SkipObjectResolution)
	if err != nil {
		return p
	}
	p.file = file
	for _, spec := range file.Imports {
		if strings.Trim(spec.Path.Value, `"`) == databasePackage && spec.Name != nil {
			p.name = spec.Name.Name
		}
	}
	return p
}

// defined is a function a package declares, at the top level or as a local
// bound to a function literal, and where it sits.
type defined struct {
	name  string
	path  string
	span  lines
	ident *ast.Ident
}

// oneEngine is, per file of one package, the lines that run on one engine
// alone.
//
// A test's dbtest.Only call runs its closure on the one engine it names, so
// every line from the call to its closing parenthesis is one engine's. So is
// a function of the package every reference to which sits on such a line: a
// closure handed to Only by name, or a helper called only from inside one.
// That is settled to a fixed point, since a helper can call another. A
// reference is matched by name, so a shadowing name or a field spelled the
// same counts as a use elsewhere, and the function stays read.
func oneEngine(files []parsed) map[string][]lines {
	spans := map[string][]lines{}
	var defs []defined
	uses := map[string][]struct {
		path string
		line int
		at   *ast.Ident
	}{}
	for _, f := range files {
		if f.file == nil {
			continue
		}
		ast.Inspect(f.file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Only" {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "dbtest" {
					spans[f.path] = append(spans[f.path], spanOf(f.fset, n))
				}
			case *ast.FuncDecl:
				if n.Recv == nil {
					defs = append(defs, defined{n.Name.Name, f.path, spanOf(f.fset, n), n.Name})
				}
			case *ast.AssignStmt:
				if len(n.Lhs) == 1 && len(n.Rhs) == 1 {
					if id, ok := n.Lhs[0].(*ast.Ident); ok {
						if _, ok := n.Rhs[0].(*ast.FuncLit); ok {
							defs = append(defs, defined{id.Name, f.path, spanOf(f.fset, n), id})
						}
					}
				}
			case *ast.Ident:
				uses[n.Name] = append(uses[n.Name], struct {
					path string
					line int
					at   *ast.Ident
				}{f.path, f.fset.Position(n.Pos()).Line, n})
			}
			return true
		})
	}
	inside := func(path string, line int) bool {
		for _, s := range spans[path] {
			if s.holds(line) {
				return true
			}
		}
		return false
	}
	settled := make([]bool, len(defs))
	for changed := true; changed; {
		changed = false
		for i, d := range defs {
			if settled[i] {
				continue
			}
			seen, outside := 0, false
			for _, u := range uses[d.name] {
				if u.at == d.ident {
					continue
				}
				seen++
				if !inside(u.path, u.line) {
					outside = true
					break
				}
			}
			if seen > 0 && !outside {
				settled[i] = true
				spans[d.path] = append(spans[d.path], d.span)
				changed = true
			}
		}
	}
	return spans
}

// allowedPath is whether a path is one where an engine may be named.
func allowedPath(path string) bool {
	for _, where := range allowed {
		if strings.HasPrefix(path, where) {
			return true
		}
	}
	return false
}

// violations is every line of one file that asks an engine directly, outside
// where that is allowed, reading the file as a package of its own.
func violations(path string, text []byte) []string {
	return packageViolations([]parsed{parse(path, text)})
}

// packageViolations is every line of one package's files that asks an engine
// directly, outside where that is allowed. A file on the allowed list has
// none.
func packageViolations(files []parsed) []string {
	only := oneEngine(files)
	var bad []string
	for _, f := range files {
		if allowedPath(f.path) {
			continue
		}
		constant := engineConstant(f.name)
		for i, line := range strings.Split(string(f.text), "\n") {
			// Comments name engines constantly, and correctly: what is being
			// looked for is code that branches on one.
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
				continue
			}
			// Choosing which engine a test runs on is not branching a query
			// on one: what runs inside dbtest.Only runs on that engine alone.
			if slices.ContainsFunc(only[f.path], func(s lines) bool { return s.holds(i + 1) }) {
				continue
			}
			line = selecting.ReplaceAllString(line, "")
			if match := asks(line, constant); match != "" {
				bad = append(bad, fmt.Sprintf("%s:%d: %s", f.path, i+1, match))
			}
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
	// A package is read whole, since a helper in one file can be called
	// only from a one-engine closure in another.
	packages := map[string][]parsed{}
	// web holds the interface, which reaches no engine at all: it talks to
	// this server over HTTP.
	read, err := walk.Only(".go", []string{"web"}, func(path string, text []byte) error {
		dir := filepath.Dir(path)
		packages[dir] = append(packages[dir], parse(path, text))
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
	var bad []string
	for _, files := range packages {
		bad = append(bad, packageViolations(files)...)
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
