// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// boundedRefusals names every function in a file that compares a status code
// as less than 400, as "file:function".
func boundedRefusals(file *ast.File, name string) []string {
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			compared, ok := n.(*ast.BinaryExpr)
			if !ok || compared.Op != token.LSS {
				return true
			}
			code, ok := compared.X.(*ast.SelectorExpr)
			bound, isLiteral := compared.Y.(*ast.BasicLit)
			if ok && code.Sel.Name == "Code" && isLiteral && bound.Value == "400" {
				found = true
			}
			return true
		})
		if found {
			out = append(out, name+":"+fn.Name.Name)
		}
	}
	return out
}

// awaitingRebase holds the functions whose bounded assertions are rewritten on
// branches not yet merged. An entry that no longer compares fails the test
// below, so each is removed as its branch lands.
var awaitingRebase = []string{
	"enter_test.go:TestARecordedSummaryGoesThroughTheSamePolicyAsAJustification",
}

// A refusal is asserted as the exact status it answers with. A bound below 400
// also holds for a panic answered 500, a route that moved and answers 404 or
// 405, and a 403 that says a hidden product exists.
func TestARefusalIsAssertedAsItsExactStatus(t *testing.T) {
	names, err := filepath.Glob("*_test.go")
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
		if !slices.Contains(awaitingRebase, each) {
			t.Errorf("%s asserts a refusal as a status below 400; use refusedWith with the exact status", each)
		}
	}
	for _, each := range awaitingRebase {
		if !slices.Contains(bounded, each) {
			t.Errorf("%s no longer compares against 400; remove it from awaitingRebase", each)
		}
	}
}

// The detection reports a bounded comparison and leaves an exact one alone.
func TestABoundedRefusalIsDetected(t *testing.T) {
	const source = `package x
func bounded() { if got.Code < 400 { fail() } }
func exact() { if got.Code != 404 { fail() } }
func bothSides() { if got.Code < 400 || got.Code >= 500 { fail() } }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x_test.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(boundedRefusals(file, "x_test.go"), ",")
	if want := "x_test.go:bounded,x_test.go:bothSides"; got != want {
		t.Errorf("reported %q, want %q", got, want)
	}
}
