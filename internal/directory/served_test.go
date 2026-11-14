// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package directory_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Nothing in this deployment serves the directory.
//
// The whole shape of this area rests on it: the application leaves no
// unauthenticated route at all, and the directory is files anybody may fetch.
// A route that served them would be that route, and it would be added by
// somebody who meant well — an endpoint to preview the feed, a handler to
// fetch one document.
//
// Asked of everything the serving packages depend on, directly or through
// another package, rather than of the routes. A handler cannot serve what its
// program cannot reach, and a check over route paths would pass a handler that
// read the store directly and served the same bytes under any name it liked.
//
// The store the directory is written to is a type of this package, so a
// serving package holding it imports this one and is reported here. Handed
// the storage it wraps instead, a handler would import nothing of this
// package; the wiring never has that storage outside the type.
func TestNothingInThisDeploymentServesTheDirectory(t *testing.T) {
	const mine = "github.com/nexthop-ai/openpsirt/internal/directory"
	listed, err := exec.CommandContext(t.Context(), "go", "list", "-deps",
		"-f", "{{.ImportPath}}", "../httpapi", "../webui").Output()
	if err != nil {
		t.Fatalf("listing what the serving packages depend on: %v", err)
	}
	read := 0
	for _, dependency := range strings.Fields(string(listed)) {
		read++
		if dependency == mine {
			t.Error("a serving package reaches the published advisory directory, so " +
				"something in this deployment can serve it")
		}
	}
	// A listing that came back empty is a check that read nothing and
	// reported the same clean answer.
	if read == 0 {
		t.Fatal("no dependency of the serving packages was listed, so this checked nothing")
	}
}

// storeType is the type the program holds the directory's store in.
func storeType(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && pkg.Name == "directory" && selector.Sel.Name == "Store"
}

// storeHeldIn is every use of the directory's store in these Go sources of
// the program, and the ones that do something other than carry it to the
// writer.
//
// The names holding it are read from the source: a field, variable or
// parameter declared as a store, and a name assigned what a function
// answering a store returns. A use carries it when it is the name declared or
// assigned, is assigned to a name of its own, passes it on by a composite
// literal's field of its own name, hands it to directory.New, or compares it
// with nil. Under any other name it would leave the names this follows.
func storeHeldIn(sources map[string][]byte) (uses int, other []string, err error) {
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for name, source := range sources {
		file, err := parser.ParseFile(fset, name, source, 0)
		if err != nil {
			return 0, nil, err
		}
		files[name] = file
	}
	held, makers := map[string]bool{}, map[string]bool{}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.Field:
				if storeType(node.Type) {
					for _, name := range node.Names {
						held[name.Name] = true
					}
				}
			case *ast.ValueSpec:
				if node.Type != nil && storeType(node.Type) {
					for _, name := range node.Names {
						held[name.Name] = true
					}
				}
			case *ast.FuncDecl:
				if node.Type.Results != nil && slices.ContainsFunc(node.Type.Results.List,
					func(f *ast.Field) bool { return storeType(f.Type) }) {
					makers[node.Name.Name] = true
				}
			}
			return true
		})
	}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Rhs) == 1 {
				if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
					if callee, ok := call.Fun.(*ast.Ident); ok && makers[callee.Name] {
						if name, ok := assign.Lhs[0].(*ast.Ident); ok {
							held[name.Name] = true
						}
					}
				}
			}
			return true
		})
	}
	for _, file := range files {
		imported := map[string]bool{}
		for _, spec := range file.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			local := filepath.Base(path)
			if spec.Name != nil {
				local = spec.Name.Name
			}
			imported[local] = true
		}
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			parent := ast.Node(nil)
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, n)
			var named string
			var at ast.Node
			switch node := n.(type) {
			case *ast.SelectorExpr:
				named, at = node.Sel.Name, node
			case *ast.Ident:
				if selector, ok := parent.(*ast.SelectorExpr); ok && (selector.Sel == node ||
					imported[node.Name]) {
					return true
				}
				named, at = node.Name, node
			default:
				return true
			}
			if !held[named] {
				return true
			}
			uses++
			if !carries(parent, at) {
				other = append(other, fset.Position(at.Pos()).String())
			}
			return true
		})
	}
	slices.Sort(other)
	return uses, other, nil
}

// carries reports whether a use of the store only declares, passes on, hands
// to the writer or tests it.
func carries(parent ast.Node, at ast.Node) bool {
	switch p := parent.(type) {
	case *ast.Field:
		return slices.ContainsFunc(p.Names, func(name *ast.Ident) bool { return name == at })
	case *ast.ValueSpec:
		return slices.ContainsFunc(p.Names, func(name *ast.Ident) bool { return name == at })
	case *ast.AssignStmt:
		if slices.Contains(p.Lhs, at.(ast.Expr)) {
			return true
		}
		i := slices.Index(p.Rhs, at.(ast.Expr))
		return i >= 0 && len(p.Lhs) == len(p.Rhs) && heldName(p.Lhs[i]) == heldName(at)
	case *ast.KeyValueExpr:
		if p.Key == at {
			return true
		}
		key, ok := p.Key.(*ast.Ident)
		return ok && key.Name == heldName(at)
	case *ast.BinaryExpr:
		other := p.X
		if other == at {
			other = p.Y
		}
		literal, ok := other.(*ast.Ident)
		return ok && literal.Name == "nil" && (p.Op == token.EQL || p.Op == token.NEQ)
	case *ast.CallExpr:
		selector, ok := p.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		pkg, ok := selector.X.(*ast.Ident)
		return ok && pkg.Name == "directory" && selector.Sel.Name == "New"
	}
	return false
}

// heldName is the name a use of the store reads it by.
func heldName(at ast.Node) string {
	switch node := at.(type) {
	case *ast.SelectorExpr:
		return node.Sel.Name
	case *ast.Ident:
		return node.Name
	}
	return ""
}

// The program composing the served handler holds the store, and cannot be
// listed above, because it must import this package to build the writer. It
// carries the store from where it is opened to directory.New and nowhere else.
func TestTheProgramCarriesTheStoreOnlyToTheWriter(t *testing.T) {
	dir := filepath.Join("..", "..", "cmd", "openpsirt")
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string][]byte{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name) //nolint:gosec // the program's own source
		if err != nil {
			t.Fatal(err)
		}
		sources[name] = source
	}
	uses, other, err := storeHeldIn(sources)
	if err != nil {
		t.Fatal(err)
	}
	if uses == 0 {
		t.Fatal("the program holds the directory's store nowhere, so this checked nothing")
	}
	for _, at := range other {
		t.Errorf("%s uses the directory's store for something other than writing it", at)
	}
	t.Logf("examined %d uses of the directory's store", uses)
}

func TestAStoreUsedOtherThanByTheWriterIsReported(t *testing.T) {
	const source = `package main
type held struct{ store *directory.Store }
func open() (*directory.Store, error) { return nil, nil }
func carried() {
	store, err := open()
	h := held{store: store}
	if store != nil { directory.New(db, h.store) }
	_ = err
}
func served() { serve(h.store) }
func renamed() { x := store; serve(x) }
func refiled() { _ = handler{files: h.store} }
`
	uses, other, err := storeHeldIn(map[string][]byte{"main.go": []byte(source)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"main.go:10:", "main.go:11:", "main.go:12:"}
	if uses == 0 || len(other) != len(want) {
		t.Fatalf("examined %d uses and reported %v, want one each in served, renamed and refiled", uses, other)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(other[i], prefix) {
			t.Errorf("reported %s, want a use at %s", other[i], prefix)
		}
	}
}
