// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command subjected reports a store method that queries the database with no
// subject to narrow what it reads.
//
// Visibility is enforced in the data layer, and every query carries a subject.
// A method with no subject is exactly what a leak looks like from the outside:
// a route handing it a row identifier reads whatever the identifier names,
// whoever asked. The exported methods of the stores holding findings,
// decisions, issues and inventories are read as parsed Go, and one that builds
// a query and takes no access.Subject fails the gate unless it is named in
// exempt.txt with the reason it takes none.
//
// A method queries when it builds a query or calls a function or method of its
// own package that queries, followed to a fixed point. A call is matched by
// name, so a method name shared by two receivers counts as either. What it
// does not see is a query reached through another package, or a subject taken
// and then not applied. It asks whether the subject arrives at all, which is
// the half of the rule a gate can check.
package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// packages are the stores read: what they hold is what visibility is about.
var packages = []string{"internal/finding", "internal/triage", "internal/graph"}

// receivers are the types whose exported methods are store reads.
var receivers = map[string]bool{"Store": true, "Vulnerabilities": true}

// building are the calls that start a query.
var building = map[string]bool{
	"NewSelect": true, "NewUpdate": true, "NewInsert": true, "NewDelete": true, "NewRaw": true,
}

//go:embed exempt.txt
var exemptList []byte

// method is one exported store method that queries with no subject.
type method struct {
	name string // as package.Type.Method
	at   string
}

func main() {
	exempt, err := parseExempt(exemptList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "subjected:", err)
		os.Exit(1)
	}
	var found []method
	examined := 0
	for _, dir := range packages {
		some, seen, err := inPackage(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "subjected:", err)
			os.Exit(1)
		}
		found = append(found, some...)
		examined += seen
	}
	if examined == 0 {
		fmt.Fprintln(os.Stderr, "subjected: no store method was found, so this checked nothing")
		os.Exit(1)
	}
	failed := false
	named := map[string]bool{}
	for _, one := range found {
		named[one.name] = true
		if _, ok := exempt[one.name]; !ok {
			if !failed {
				fmt.Fprintln(os.Stderr, "these store methods query with no subject to narrow by, "+
					"and are not named in internal/tools/subjected/exempt.txt:")
			}
			failed = true
			fmt.Fprintf(os.Stderr, "  %s: %s\n", one.at, one.name)
		}
	}
	var stale []string
	for name := range exempt {
		if !named[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	for _, name := range stale {
		failed = true
		fmt.Fprintf(os.Stderr, "  %s is exempt in internal/tools/subjected/exempt.txt and "+
			"no longer queries without a subject\n", name)
	}
	if failed {
		os.Exit(1)
	}
	fmt.Printf("every store method that queries takes a subject or says why not "+
		"(%d methods examined, %d exempt)\n", examined, len(exempt))
}

// inPackage is every exported store method in one directory that queries with
// no subject, and how many store methods it examined.
func inPackage(dir string) ([]method, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	sources := map[string][]byte{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		source, err := os.ReadFile(path) //nolint:gosec // G304: this repository's own source
		if err != nil {
			return nil, 0, err
		}
		sources[path] = source
	}
	return inSources(filepath.Base(dir), sources)
}

// inSource is inPackage for one file.
func inSource(pkg, path string, source []byte) ([]method, int, error) {
	return inSources(pkg, map[string][]byte{path: source})
}

// declared is one function or method of the package, by the name a call
// reaches it under.
type declared struct {
	fn   *ast.FuncDecl
	path string
}

// inSources is inPackage over the files of one package, keyed by path.
func inSources(pkg string, sources map[string][]byte) ([]method, int, error) {
	fset := token.NewFileSet()
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var all []declared
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, sources[path], 0)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", path, err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				all = append(all, declared{fn: fn, path: path})
			}
		}
	}
	querying := queryingNames(all)

	var found []method
	examined := 0
	for _, one := range all {
		fn := one.fn
		if fn.Recv == nil || !fn.Name.IsExported() {
			continue
		}
		receiver := receiverOf(fn)
		if !receivers[receiver] {
			continue
		}
		examined++
		if takesSubject(fn) || !querying[nameOf(fn)] {
			continue
		}
		found = append(found, method{
			name: pkg + "." + receiver + "." + fn.Name.Name,
			at:   fmt.Sprintf("%s:%d", one.path, fset.Position(fn.Pos()).Line),
		})
	}
	return found, examined, nil
}

// nameOf is the name a call reaches a declaration under: ".Name" for a method,
// whatever its receiver, and "Name" for a function.
func nameOf(fn *ast.FuncDecl) string {
	if fn.Recv != nil {
		return "." + fn.Name.Name
	}
	return fn.Name.Name
}

// queryingNames is every declaration name that builds a query or calls one
// that does, followed to a fixed point.
func queryingNames(all []declared) map[string]bool {
	querying := map[string]bool{}
	calls := map[string][]string{}
	for _, one := range all {
		name := nameOf(one.fn)
		if builds(one.fn.Body) {
			querying[name] = true
		}
		calls[name] = append(calls[name], calledBy(one.fn.Body)...)
	}
	for changed := true; changed; {
		changed = false
		for name, called := range calls {
			if querying[name] {
				continue
			}
			for _, callee := range called {
				if querying[callee] {
					querying[name], changed = true, true
					break
				}
			}
		}
	}
	return querying
}

// calledBy is every name a body calls, in the form nameOf gives a declaration.
func calledBy(body *ast.BlockStmt) []string {
	var called []string
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			called = append(called, fun.Name)
		case *ast.SelectorExpr:
			called = append(called, "."+fun.Sel.Name)
		}
		return true
	})
	return called
}

// receiverOf is the name of the type a method is declared on.
func receiverOf(fn *ast.FuncDecl) string {
	switch t := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if named, ok := t.X.(*ast.Ident); ok {
			return named.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// takesSubject reports whether a method takes an access.Subject.
func takesSubject(fn *ast.FuncDecl) bool {
	for _, param := range fn.Type.Params.List {
		if selector, ok := param.Type.(*ast.SelectorExpr); ok && selector.Sel.Name == "Subject" {
			if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "access" {
				return true
			}
		}
	}
	return false
}

// builds reports whether a body starts a query itself.
func builds(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok && building[selector.Sel.Name] {
			found = true
		}
		return !found
	})
	return found
}

// parseExempt reads the exempt list: one method per line as
// package.Type.Method, a tab or spaces, and the reason it takes no subject.
// A line with no reason is refused, because the reason is the whole of what
// makes an exemption reviewable.
func parseExempt(list []byte) (map[string]string, error) {
	exempt := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(list))
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		name, reason, _ := strings.Cut(text, " ")
		if strings.TrimSpace(reason) == "" {
			return nil, fmt.Errorf("exempt.txt:%d: %s names no reason", line, name)
		}
		exempt[name] = strings.TrimSpace(reason)
	}
	return exempt, scanner.Err()
}
