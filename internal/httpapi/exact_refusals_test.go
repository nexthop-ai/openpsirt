// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// refusalStatuses are the statuses a refusal answers with, by the name
// net/http gives each. A comparison ordering a status against one of them
// holds for every refusal on one side of it rather than the one meant.
var refusalStatuses = map[string]bool{
	"StatusBadRequest": true, "StatusUnauthorized": true, "StatusPaymentRequired": true,
	"StatusForbidden": true, "StatusNotFound": true, "StatusMethodNotAllowed": true,
	"StatusNotAcceptable": true, "StatusConflict": true, "StatusGone": true,
	"StatusPreconditionFailed": true, "StatusRequestEntityTooLarge": true,
	"StatusUnsupportedMediaType": true, "StatusUnprocessableEntity": true,
	"StatusTooManyRequests": true,
}

// successStatuses are the statuses a request that was let through answers
// with. A test failing where a status is one of them asserts "anything but
// success", which a 500 satisfies.
var successStatuses = map[string]bool{
	"StatusOK": true, "StatusCreated": true, "StatusAccepted": true,
	"StatusNoContent": true, "StatusFound": true,
}

// boundedRefusals names every function in a file that asserts a refusal
// loosely, as "file:function": a status found below 400, a status ordered
// against a refusal's status, or a test failing only where a status is a
// success.
func boundedRefusals(file *ast.File, name string) []string {
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BinaryExpr:
				if ordered(node) {
					found = true
				}
			case *ast.IfStmt:
				if failsOnlyOnSuccess(node) {
					found = true
				}
			}
			return true
		})
		if found {
			out = append(out, name+":"+fn.Name.Name)
		}
	}
	return out
}

// ordered reports a status found below 400, or ordered either way against a
// refusal's status by name. Whatever holds the status — a recorder's Code, or
// a plain int a helper returned — nothing but a status is compared with these.
func ordered(compared *ast.BinaryExpr) bool {
	switch compared.Op {
	case token.LSS, token.LEQ, token.GTR, token.GEQ:
	default:
		return false
	}
	if bound, ok := compared.Y.(*ast.BasicLit); ok && bound.Value == "400" &&
		(compared.Op == token.LSS || compared.Op == token.LEQ) {
		return true
	}
	return refusalStatuses[statusNamed(compared.X)] || refusalStatuses[statusNamed(compared.Y)]
}

// failsOnlyOnSuccess reports `if status == http.StatusOK { t.Error(...) }`:
// a test that fails where a request succeeded and passes on anything else.
func failsOnlyOnSuccess(branch *ast.IfStmt) bool {
	compared, ok := branch.Cond.(*ast.BinaryExpr)
	if !ok || compared.Op != token.EQL {
		return false
	}
	if !successStatuses[statusNamed(compared.X)] && !successStatuses[statusNamed(compared.Y)] {
		return false
	}
	// The failure has to be what the branch does, not something nested in
	// it: a branch decoding a success's body fails on a decoding error.
	for _, statement := range branch.Body.List {
		expression, ok := statement.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expression.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
			switch selector.Sel.Name {
			case "Error", "Errorf", "Fatal", "Fatalf":
				return true
			}
		}
	}
	return false
}

// statusNamed is the name of an http.Status constant an expression is, or
// empty.
func statusNamed(expr ast.Expr) string {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if pkg, ok := selector.X.(*ast.Ident); !ok || pkg.Name != "http" {
		return ""
	}
	return selector.Sel.Name
}

// A refusal is asserted as the exact status it answers with. A bound below 400
// also holds for a panic answered 500, a route that moved and answers 404 or
// 405, and a 403 that says a hidden product exists.
//
// The tests are every test file in this package and the packages beneath it,
// and the shared harness, which is ordinary source in a package of its own.
func TestARefusalIsAssertedAsItsExactStatus(t *testing.T) {
	var names []string
	err := filepath.WalkDir(".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(name, ".go") {
			return err
		}
		if strings.HasSuffix(name, "_test.go") || filepath.Dir(name) == "httpapitest" {
			names = append(names, name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("no test file was found, so this checked nothing")
	}
	fset := token.NewFileSet()
	var bounded []string
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		bounded = append(bounded, boundedRefusals(file, name)...)
	}
	for _, each := range bounded {
		t.Errorf("%s asserts a refusal loosely; use RefusedWith with the exact status", each)
	}
}

// The detection reports a bounded comparison and a test failing only on success,
// and leaves an exact one, a fault check and a success check alone.
func TestABoundedRefusalIsDetected(t *testing.T) {
	const source = `package x
func bounded() { if got.Code < 400 { fail() } }
func exact() { if got.Code != 404 { fail() } }
func bothSides() { if got.Code < 400 || got.Code >= 500 { fail() } }
func bareInt() { code := ask(); if code < 400 { fail() } }
func named() { if got.Code >= http.StatusBadRequest { fail() } }
func namedBelow() { if got.Code < http.StatusNotFound { fail() } }
func fault() { if got.Code >= http.StatusInternalServerError { fail() } }
func success() { if got.Code >= http.StatusMultipleChoices { t.Fatal() } }
func anythingButSuccess() { if got.Code == http.StatusOK { t.Errorf("let through") } }
func successExpected() { if got.Code != http.StatusOK { t.Errorf("refused") } }
func decoding() { if got.Code == http.StatusCreated { if err := decode(); err != nil { t.Fatal(err) } } }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x_test.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(boundedRefusals(file, "x_test.go"), ",")
	if want := "x_test.go:bounded,x_test.go:bothSides,x_test.go:bareInt,x_test.go:named," +
		"x_test.go:namedBelow,x_test.go:anythingButSuccess"; got != want {
		t.Errorf("reported %q, want %q", got, want)
	}
}
