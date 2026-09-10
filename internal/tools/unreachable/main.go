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
	"path/filepath"
	"sort"
	"strings"
)

type decl struct {
	name string
	file string
	line int
}

// Always the working directory. It took a path once and that is a taint the
// analysis gate is right to complain about — a build-time tool that walks
// wherever it is pointed is a shape worth not having, however harmless here.
const root = "."

func main() {
	var declared []decl
	// How many times each name is written anywhere, declarations included.
	// A symbol nothing reaches is written exactly once: where it is declared.
	mentions := map[string]int{}
	fset := token.NewFileSet()

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if path != root && skipped(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		if !strings.HasSuffix(path, "_test.go") && file.Name.Name != "main" {
			for _, d := range file.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || !fn.Name.IsExported() {
					continue
				}
				at := fset.Position(fn.Pos())
				declared = append(declared, decl{fn.Name.Name, at.Filename, at.Line})
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

func skipped(name string) bool {
	switch name {
	case ".git", "bin", "node_modules", "deploy", "assets", "docs":
		return true
	}
	return strings.HasPrefix(name, ".")
}
