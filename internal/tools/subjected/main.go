// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command subjected reports a store read or write that queries the database
// with no subject to narrow what it reaches.
//
// Visibility is enforced in the data layer, and every query carries a subject.
// A method with no subject is exactly what a leak looks like from the outside:
// a route handing it a row identifier reads whatever the identifier names,
// whoever asked. Every package under internal/ is read as parsed Go, except a
// program and a package of test fixtures. A type is a store where one of its
// methods builds a query. Its exported methods, and the package's exported
// functions, that query and take no access.Subject fail the gate unless named
// in exempt.txt with the reason they take none.
//
// A declaration queries when it builds a query or calls a function or method
// of its own package that queries, followed to a fixed point. A call is
// matched by name, so a method name shared by two receivers counts as either.
// What it does not see is a query reached through another package, or a
// subject taken and then not applied. It asks whether the subject arrives at
// all, which is the half of the rule a gate can check.
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
	"path"
	"sort"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// root is the tree read, and the prefix a name is given relative to.
const root = "internal/"

// building are the calls that start a query.
var building = map[string]bool{
	"NewSelect": true, "NewUpdate": true, "NewInsert": true, "NewDelete": true, "NewRaw": true,
}

//go:embed exempt.txt
var exemptList []byte

// method is one exported store method or function that queries with no
// subject.
type method struct {
	name string // as package.Type.Method, or package.Function
	at   string
}

func main() {
	exempt, err := parseExempt(exemptList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "subjected:", err)
		os.Exit(1)
	}
	packages := map[string]map[string][]byte{}
	if _, err := walk.Sources(".go", func(file string, body []byte) error {
		if strings.HasPrefix(file, root) && !strings.HasSuffix(file, "_test.go") {
			dir := path.Dir(file)
			if packages[dir] == nil {
				packages[dir] = map[string][]byte{}
			}
			packages[dir][file] = body
		}
		return nil
	}); err != nil {
		fmt.Fprintln(os.Stderr, "subjected:", err)
		os.Exit(1)
	}
	found, examined, err := inTree(packages)
	if err != nil {
		fmt.Fprintln(os.Stderr, "subjected:", err)
		os.Exit(1)
	}
	if examined == 0 {
		fmt.Fprintln(os.Stderr, "subjected: no store method or function was found, so this checked nothing")
		os.Exit(1)
	}
	failed := false
	named := map[string]bool{}
	for _, one := range found {
		named[one.name] = true
		if _, ok := exempt[one.name]; !ok {
			if !failed {
				fmt.Fprintln(os.Stderr, "these store methods and functions query with no subject to narrow by, "+
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
	fmt.Printf("every store method and function that queries takes a subject or says why not "+
		"(%d examined, %d exempt)\n", examined, len(exempt))
}

// inTree is inSources over every package of the tree, keyed by directory and
// then by path, and how many store methods and functions it examined. A
// program and a package of test fixtures are not read: neither is reached by
// a request.
func inTree(packages map[string]map[string][]byte) ([]method, int, error) {
	dirs := make([]string, 0, len(packages))
	for dir := range packages {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	var found []method
	examined := 0
	for _, dir := range dirs {
		some, seen, err := inSources(strings.TrimPrefix(dir, root), packages[dir])
		if err != nil {
			return nil, 0, err
		}
		found = append(found, some...)
		examined += seen
	}
	return found, examined, nil
}

// inSource is inSources for one file.
func inSource(pkg, path string, source []byte) ([]method, int, error) {
	return inSources(pkg, map[string][]byte{path: source})
}

// declared is one function or method of the package, by the name a call
// reaches it under.
type declared struct {
	fn   *ast.FuncDecl
	path string
	// imported is the names its file imports packages under, so a call
	// into another package is never taken for one of this package's own.
	imported map[string]bool
}

// inSources is every exported store method and function of one package that
// queries with no subject, and how many it examined. The package is named by
// its directory under internal/, its files keyed by path. A program and a
// package of test fixtures answer nothing.
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
		if name := file.Name.Name; name == "main" || strings.HasSuffix(name, "test") {
			return nil, 0, nil
		}
		imported := importNames(file)
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				all = append(all, declared{fn: fn, path: path, imported: imported})
			}
		}
	}
	querying := queryingNames(all)
	// A store is a type one of whose methods builds a query itself.
	stores := map[string]bool{}
	for _, one := range all {
		if one.fn.Recv != nil && builds(one.fn.Body) {
			stores[receiverOf(one.fn)] = true
		}
	}

	var found []method
	examined := 0
	for _, one := range all {
		fn := one.fn
		if !fn.Name.IsExported() {
			continue
		}
		name := pkg + "." + fn.Name.Name
		if fn.Recv != nil {
			// A method of an unexported type is reached through this
			// package alone, which is what is read here.
			receiver := receiverOf(fn)
			if !stores[receiver] || !ast.IsExported(receiver) {
				continue
			}
			name = pkg + "." + receiver + "." + fn.Name.Name
		} else if !querying[nameOf(fn)] {
			continue
		}
		examined++
		if takesSubject(pkg, fn) || !querying[nameOf(fn)] {
			continue
		}
		found = append(found, method{
			name: name,
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
		calls[name] = append(calls[name], calledBy(one.fn.Body, one.imported)...)
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
// A call through an imported package's name is another package's, and left
// out.
func calledBy(body *ast.BlockStmt, imported map[string]bool) []string {
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
			if pkg, ok := fun.X.(*ast.Ident); ok && imported[pkg.Name] {
				return true
			}
			called = append(called, "."+fun.Sel.Name)
		}
		return true
	})
	return called
}

// importNames is the names a file refers to its imported packages by: the
// name given, or the last element of the path. A version suffix such as /v2
// is not a name, so the element before it is taken.
func importNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, spec := range file.Imports {
		if spec.Name != nil {
			names[spec.Name.Name] = true
			continue
		}
		elements := strings.Split(strings.Trim(spec.Path.Value, `"`), "/")
		last := elements[len(elements)-1]
		if len(elements) > 1 && len(last) > 1 && last[0] == 'v' && strings.Trim(last[1:], "0123456789") == "" {
			last = elements[len(elements)-2]
		}
		names[last] = true
	}
	return names
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

// takesSubject reports whether a declaration takes an access.Subject, spelled
// Subject inside the access package itself.
func takesSubject(pkg string, fn *ast.FuncDecl) bool {
	for _, param := range fn.Type.Params.List {
		switch t := param.Type.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := t.X.(*ast.Ident); ok && pkg.Name == "access" && t.Sel.Name == "Subject" {
				return true
			}
		case *ast.Ident:
			if pkg == "access" && t.Name == "Subject" {
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
