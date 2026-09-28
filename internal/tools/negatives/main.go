// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command negatives reports a 404 built from an error's own text.
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
// It does not cover an error arm that answers the fixed 404 without
// asking which error it is. That has the same wrong status with nothing
// disclosed, and "did this arm test the sentinel" is a question about control
// flow that reading the text cannot answer. A gate that pretended to answer it
// would be worse than one that says where it stops.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"unicode"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// builtFromError reports whether a call is a 404 whose message comes from an
// error value rather than from a sentence the code chose.
//
// Two shapes publish one. An error passed after the message is appended to the
// body as a detail by the framework, whatever it is called. And any argument
// reading an error's text — a method named Error called with nothing, on any
// value — puts that text in the message. A sentinel a package declares, read
// as `pkg.ErrName.Error()`, is a sentence the code chose and is left alone.
func builtFromError(call *ast.CallExpr) bool {
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
	found := false
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			inner, ok := n.(*ast.CallExpr)
			if !ok || len(inner.Args) != 0 {
				return !found
			}
			method, ok := inner.Fun.(*ast.SelectorExpr)
			if ok && method.Sel.Name == "Error" && !sentinel(method.X) {
				found = true
			}
			return !found
		})
	}
	return found
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
// to a parser and three to a pattern.
func builtIn(path string, src []byte) ([]int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var lines []int
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && builtFromError(call) {
			lines = append(lines, fset.Position(call.Pos()).Line)
		}
		return true
	})
	return lines, nil
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
	"internal/httpapi/absent.go": "undeclared, reached only for catalog.ErrNotFound",
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
			"exception(s) (%d files)\n", len(allowed), read)
		return
	}
	for _, one := range bad {
		fmt.Fprintln(os.Stderr, one)
	}
	fmt.Fprintf(os.Stderr,
		"\n%d refusal(s) tell a caller a name reaches nothing, in words an error chose.\n",
		len(bad))
	os.Exit(1)
}
