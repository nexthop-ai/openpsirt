// Command reserved reports invented SQL names that an engine reserves.
//
// Queries here are written once and run against four engines, and a name this
// code makes up — an alias on a subquery, a column an expression is given so a
// later clause can refer to it — is not checked by anything until one of them
// refuses to parse it. The four do not reserve the same words: `groups` is
// reserved by PostgreSQL and not by MySQL, `usage` by MySQL and not by
// PostgreSQL, and the day somebody writes `AS usage` the suite is green on
// three engines and a production deployment on the fourth stops answering.
//
// So the names are checked against the union of what the four reserve. Nothing
// currently collides — that is the point of running it now rather than after
// one does.
//
// **Only the names this code invents.** A column that exists in the schema is
// not an invented name: it was declared in a migration, which every engine has
// already accepted, and quoting or renaming those is a different job. What
// this reads is `AS <word>`, which is exactly the syntax for making one up.
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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// invented matches a name this code makes up: AS, then a bare word. A quoted
// one is already safe, and that is the fix when this reports something.
var invented = regexp.MustCompile(`(?i)\bAS\s+([A-Za-z_][A-Za-z0-9_]*)\b`)

// writing is the query builder's methods that take SQL as text.
//
// Matched by name rather than by resolving the type, which is the same
// crudeness the two gates beside this one accept: something else with a method
// called Where is read as SQL and reports a word it should not. That direction
// is the safe one — it can only ask somebody to rename a thing — and the
// alternative is a type checker in a program whose whole job is to grep.
//
// Naming them is what keeps prose out. Nearly every English sentence in this
// repository contains the word "as", and a check that read doc comments
// reported eighteen names, every one of them a word in a sentence.
var writing = map[string]bool{
	"TableExpr": true, "ColumnExpr": true, "GroupExpr": true, "OrderExpr": true,
	"Having": true, "Where": true, "Join": true, "JoinOn": true,
	"WhereOr": true, "Raw": true, "NewRaw": true, "Exec": true,
	"ExecContext": true, "QueryContext": true, "Set": true,
}

// found is one place a name was invented.
type found struct {
	word string
	file string
	line int
}

func main() {
	reserved := map[string]bool{}
	for _, word := range reservedWords {
		reserved[word] = true
	}

	var bad []found
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", "site", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			named, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !writing[named.Sel.Name] {
				return true
			}
			for _, arg := range call.Args {
				text, at, ok := literal(fset, arg)
				if !ok {
					continue
				}
				for _, match := range invented.FindAllStringSubmatch(text, -1) {
					word := strings.ToLower(match[1])
					if reserved[word] {
						bad = append(bad, found{word: word, file: path, line: at})
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if len(bad) == 0 {
		fmt.Printf("no invented name collides with a word any of the four engines reserves "+
			"(%d words checked)\n", len(reservedWords))
		return
	}
	sort.Slice(bad, func(i, j int) bool {
		if bad[i].file != bad[j].file {
			return bad[i].file < bad[j].file
		}
		return bad[i].line < bad[j].line
	})
	for _, one := range bad {
		fmt.Fprintf(os.Stderr, "%s:%d: %q is reserved by one of the four engines. "+
			"Quote it, or call it something else\n", one.file, one.line, one.word)
	}
	fmt.Fprintf(os.Stderr, "\n%d invented name(s) an engine will refuse to parse.\n", len(bad))
	os.Exit(1)
}

// literal reads a string argument, following the concatenations these queries
// are written as: a clause built from three pieces on three lines is one
// string to the engine and has to be one string here.
func literal(fset *token.FileSet, node ast.Expr) (string, int, bool) {
	switch typed := node.(type) {
	case *ast.BasicLit:
		if typed.Kind != token.STRING {
			return "", 0, false
		}
		text, err := strconv.Unquote(typed.Value)
		if err != nil {
			// A raw string with something Unquote will not take. The value
			// itself is close enough to search.
			text = typed.Value
		}
		return text, fset.Position(typed.Pos()).Line, true
	case *ast.BinaryExpr:
		if typed.Op != token.ADD {
			return "", 0, false
		}
		left, at, leftOK := literal(fset, typed.X)
		right, rightAt, rightOK := literal(fset, typed.Y)
		if !leftOK && !rightOK {
			return "", 0, false
		}
		if !leftOK {
			return right, rightAt, true
		}
		return left + right, at, true
	}
	return "", 0, false
}
