// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command negatives reports a 404 built from an error's own text, and an error
// arm that answers 404 without asking which error it is.
//
// A 404 asserts that a name reaches nothing. Building its body from an
// error publishes whatever that error carried, and where the reader under it
// returns the driver's message unwrapped, the two compound: a connection
// failure reaches an authenticated caller as "that product does not exist",
// with the database host, port and driver in the detail — a false statement
// about the catalog and the address of the server in one answer.
//
// Only 404. The other refusals publish a store's own sentence deliberately,
// and which of the two an error is has already been decided for them by the
// helper that tells a refusal from a query that failed. Widened to every
// status it would flag every one of those deliberate lines and teach people to
// ignore it.
//
// The second shape is `if err != nil {` whose first statement answers a fixed
// 404. It has the wrong status with nothing disclosed: a read that could not
// be made answers "that does not exist", and inside a transaction the cause the
// retry helper reads is gone. The helper that splits the two, core.Absent, is what
// such an arm calls instead. The gate reads the arm's first statement only, so
// an arm that tests the sentinel first and then answers 404 passes, and one
// that answers 404 after some other statement is not seen.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// builtFromError reports whether a call is a 404 whose message comes from an
// error value rather than from a sentence the code chose.
//
// Two shapes publish one. An error passed after the message is appended to the
// body as a detail by the framework, whatever it is called. And any argument
// carrying an error's text puts that text in the message, as readsError says.
// `bound` holds the names in the enclosing function that were given an error's
// text before the call.
func builtFromError(call *ast.CallExpr, bound map[string]bool) bool {
	fun, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || fun.Sel.Name != "Error404NotFound" {
		return false
	}
	if pkg, ok := fun.X.(*ast.Ident); !ok || pkg.Name != "huma" {
		return false
	}
	if len(call.Args) > 1 {
		return true
	}
	for _, arg := range call.Args {
		if readsError(arg, bound) {
			return true
		}
	}
	return false
}

// readsError reports whether an expression carries an error's text.
//
// Three shapes do: a method named Error called with nothing, on any value; a
// formatting call handed a value named like an error, which formats its text;
// and a name given one of those earlier in the function. A sentinel a package
// declares, read as `pkg.ErrName.Error()`, is a sentence the code chose and is
// left alone.
func readsError(x ast.Expr, bound map[string]bool) bool {
	found := false
	ast.Inspect(x, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			found = found || bound[n.Name]
		case *ast.CallExpr:
			method, ok := n.Fun.(*ast.SelectorExpr)
			if !ok {
				break
			}
			if len(n.Args) == 0 && method.Sel.Name == "Error" && !sentinel(method.X) {
				found = true
			}
			if pkg, ok := method.X.(*ast.Ident); ok && pkg.Name == "fmt" && formats[method.Sel.Name] {
				for _, arg := range n.Args {
					if name, ok := arg.(*ast.Ident); ok && errorNamed(name.Name) {
						found = true
					}
				}
			}
		}
		return !found
	})
	return found
}

// formats are the fmt functions that write their arguments' text into the
// string they return.
var formats = map[string]bool{"Sprint": true, "Sprintf": true, "Sprintln": true, "Errorf": true}

// errorNamed is whether a name is spelled the way an error is named here:
// err, or a word ending in Err, or err followed by a word.
func errorNamed(name string) bool {
	if name == "err" || strings.HasSuffix(name, "Err") && len(name) > 3 {
		return true
	}
	return strings.HasPrefix(name, "err") && len(name) > 3 && unicode.IsUpper(rune(name[3]))
}

// boundIn is every name a function body gives an error's text, by assignment
// or declaration. Read to a fixed point, so a name bound from another such name
// is one too.
func boundIn(body ast.Node) map[string]bool {
	bound := map[string]bool{}
	for changed := true; changed; {
		changed = false
		mark := func(names []ast.Expr, values []ast.Expr) {
			for i, value := range values {
				if i >= len(names) || !readsError(value, bound) {
					continue
				}
				if name, ok := names[i].(*ast.Ident); ok && name.Name != "_" && !bound[name.Name] {
					bound[name.Name] = true
					changed = true
				}
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				mark(n.Lhs, n.Rhs)
			case *ast.ValueSpec:
				names := make([]ast.Expr, len(n.Names))
				for i, name := range n.Names {
					names[i] = name
				}
				mark(names, n.Values)
			}
			return true
		})
	}
	return bound
}

// sentinel is whether an expression is a package's exported error value,
// `pkg.ErrName`, which holds a sentence rather than anything a driver wrote.
func sentinel(x ast.Expr) bool {
	sel, ok := x.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if _, ok := sel.X.(*ast.Ident); !ok {
		return false
	}
	name := sel.Sel.Name
	return strings.HasPrefix(name, "Err") && len(name) > 3 && unicode.IsUpper(rune(name[3]))
}

// builtIn is the line of every such 404 in a file's source.
//
// Parsed rather than matched line by line: a call spread over lines, an error
// under any name, and an error passed as a second argument are all one shape
// to a parser and three to a pattern. Names are followed within the top-level
// declaration that binds them.
func builtIn(path string, src []byte) ([]int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var lines []int
	for _, decl := range file.Decls {
		bound := boundIn(decl)
		ast.Inspect(decl, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && builtFromError(call, bound) {
				lines = append(lines, fset.Position(call.Pos()).Line)
			}
			return true
		})
	}
	return lines, nil
}

// collapsing matches an error arm that tests nothing but the error's presence.
var collapsing = regexp.MustCompile(`\berr != nil(\s*\|\|[^{]*)?\s*\{\s*$`)

// absence matches a return answering a fixed 404, behind any number of other
// return values.
var absence = regexp.MustCompile(
	`^\s*return\s+(?:[^,()]+,\s*)*(?:(?:\w+\.)?[nN]oSuch\w*\(|huma\.Error404NotFound\()`)

// collapses reports the lines of body that open an error arm answering a fixed
// 404 whatever the error was, as one-based line numbers.
func collapses(body string) []int {
	lines := strings.Split(body, "\n")
	var found []int
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || !collapsing.MatchString(line) ||
			strings.Contains(line, "errors.Is") {
			continue
		}
		next := i + 1
		for next < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[next]), "//") {
			next++
		}
		if next < len(lines) && absence.MatchString(lines[next]) {
			found = append(found, i+1)
		}
	}
	return found
}

// allowed is the one place a 404 may publish an error's text, and why.
//
// The catalog's own not-declared error is composed from the names the caller
// supplied and fixed words. Nothing a driver wrote can be in it, and a
// pipeline whose upload was refused has to be told which of the product, the
// branch and the variant was not declared. The arm is reached only once the
// sentinel has been tested — a property of one audited function rather than
// anything this gate can see, so the exemption is named rather than inferred.
var allowed = map[string]string{
	"internal/httpapi/core/absent.go": "undeclared, reached only for catalog.ErrNotFound",
}

func main() {
	var bad []string
	read, err := walk.Sources(".go", func(path string, body []byte) error {
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if _, ok := allowed[path]; ok {
			return nil
		}
		for _, at := range collapses(string(body)) {
			bad = append(bad, fmt.Sprintf(
				"%s:%d: an error arm answers 404 whatever the error was. A read that "+
					"could not be made is then \"that does not exist\", and inside a "+
					"transaction the cause the retry helper reads is gone. Answer "+
					"through core.Absent, which gives the 404 for the sentinel and a "+
					"logged fault for everything else", path, at))
		}
		lines, err := builtIn(path, body)
		if err != nil {
			return err
		}
		source := strings.Split(string(body), "\n")
		for _, at := range lines {
			bad = append(bad, fmt.Sprintf(
				"%s:%d: a 404 built from an error's own text. It asserts that a name "+
					"reaches nothing, and publishes whatever the error carried — for a "+
					"store read, the driver's message. Split on the sentinel, choose "+
					"the sentence here, and send the error to the log:\n\t%s",
				path, at, strings.TrimSpace(source[at-1])))
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(bad) == 0 {
		fmt.Printf("no 404 is built from an error's own text, beside the %d named "+
			"exception(s), and no error arm answers 404 whatever the error was "+
			"(%d files)\n", len(allowed), read)
		return
	}
	for _, one := range bad {
		fmt.Fprintln(os.Stderr, one)
	}
	fmt.Fprintf(os.Stderr,
		"\n%d refusal(s) tell a caller a name reaches nothing without knowing it does.\n",
		len(bad))
	os.Exit(1)
}
