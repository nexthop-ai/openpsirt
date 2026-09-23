// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command unreachable reports exported functions and methods that nothing
// outside their own declaration ever names.
//
// The static analysis gate reports unused *unexported* symbols and stops
// there, which leaves a whole class of defect invisible: a store method with
// no route to it, a renderer nothing renders with, a rule checked in a second
// place nothing reaches. Ten of those were found by hand in one review, and
// every one of them looked like working code — the reasoning was sound, the
// tests passed, and none of it ran.
//
// Deliberately crude. It counts identifiers rather than resolving types, so a
// method reached only through an interface counts as reached by name alone.
// That errs toward saying nothing, which is the right direction: a check that
// accuses working code is a check somebody turns off.
//
// A symbol named only by tests still counts as named. Whether a thing that
// only its own tests reach should exist is a judgment about intent, and this
// reports facts.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

type decl struct {
	name string
	file string
	line int
}

func main() {
	var declared []decl
	// The number of times each name is written anywhere, declarations included.
	// A symbol nothing reaches is written exactly once: where it is declared.
	mentions := map[string]int{}
	fset := token.NewFileSet()

	// web holds the interface, which is TypeScript, and deploy, assets and
	// docs hold no Go either — but they are not named here, because reading a
	// directory with no Go in it costs nothing and a skip list is where a
	// gate quietly stops looking at part of the tree.
	read, err := walk.Sources(".go", func(path string, _ []byte) error {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		if !strings.HasSuffix(path, "_test.go") && file.Name.Name != "main" {
			for _, d := range file.Decls {
				for _, name := range exportedIn(d) {
					at := fset.Position(d.Pos())
					declared = append(declared, decl{name, at.Filename, at.Line})
				}
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch used := n.(type) {
			case *ast.SelectorExpr:
				mentions[used.Sel.Name]++
			case *ast.Ident:
				mentions[used.Name]++
			}
			return true
		})
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var orphans []decl
	for _, d := range declared {
		if mentions[d.name] <= 1 && !satisfiesSomething(d.name) {
			orphans = append(orphans, d)
		}
	}

	sort.Slice(orphans, func(i, j int) bool {
		if orphans[i].file != orphans[j].file {
			return orphans[i].file < orphans[j].file
		}
		return orphans[i].line < orphans[j].line
	})
	for _, o := range orphans {
		fmt.Printf("%s:%d: %s is exported and nothing names it\n", o.file, o.line, o.name)
	}
	if len(orphans) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d exported symbol(s) nothing reaches. Either something "+
			"should, or they should go — that is how a control ends up guarding a door "+
			"nobody can walk through.\n", len(orphans))
		os.Exit(1)
	}
	// Said with a count, like the gates beside it. Silence on success and
	// silence on a walk that reached nothing are the same output, and this is
	// the gate AGENTS.md leans on.
	fmt.Printf("every exported symbol is named by something (%d in %d files)\n", len(declared), read)
}

// exportedIn is every exported name one declaration makes.
//
// Types, values and constants as well as functions. Only functions were
// read, so a request type registered on no operation sat fully specified and
// unreachable — declared, documented, and in neither the OpenAPI document nor
// the generated client, because nothing put it there. A type is exactly the
// shape this gate is least able to be talked out of: it compiles, it reads as
// intent, and nothing calls it.
func exportedIn(d ast.Decl) []string {
	switch typed := d.(type) {
	case *ast.FuncDecl:
		if typed.Name.IsExported() {
			return []string{typed.Name.Name}
		}
	case *ast.GenDecl:
		var names []string
		for _, spec := range typed.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				if s.Name.IsExported() {
					names = append(names, s.Name.Name)
				}
			case *ast.ValueSpec:
				for _, one := range s.Names {
					if one.IsExported() {
						names = append(names, one.Name)
					}
				}
			}
		}
		return names
	}
	return nil
}

// satisfiesSomething covers the names a standard interface calls, which are
// reached by the runtime rather than by anything written here.
func satisfiesSomething(name string) bool {
	switch name {
	case "Error", "String", "Unwrap", "Is", "As",
		"MarshalJSON", "UnmarshalJSON", "MarshalText", "UnmarshalText",
		"ServeHTTP", "Read", "Write", "Close", "Len", "Less", "Swap":
		return true
	}
	return false
}
