// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every day and moment the server writes as text is written in UTC.
//
// A time read back from a database carries the server's zone, so a day
// formatted from it is the server's day: 23:00 at seven hours west of UTC is
// the next day in UTC. CI runs in UTC, where every conversion is a no-op, so
// no test of a response can fail for a missing one. This reads the source
// instead: a time layout passed to Format is formatted from a receiver that
// is itself a call to UTC.
func TestEveryTimeTheServerFormatsIsFormattedInUTC(t *testing.T) {
	examined := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		formats, outside := formatsOutsideUTC(fset, file)
		examined += formats
		for _, at := range outside {
			t.Errorf("%s formats a time without converting it to UTC first", at)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if examined == 0 {
		t.Fatal("no time was formatted anywhere in the source, so this checked nothing")
	}
}

func TestTheUTCFormatGateTellsTheTwoShapesApart(t *testing.T) {
	const src = `package p

import "time"

func f(at time.Time) (string, string, string) {
	return at.UTC().Format(time.DateOnly), at.Format(time.RFC3339), at.Format("2006-01-02")
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	formats, outside := formatsOutsideUTC(fset, file)
	if formats != 3 || len(outside) != 2 {
		t.Errorf("read %d formats and %d outside UTC (%v), want 3 and the two without a conversion",
			formats, len(outside), outside)
	}
}

// formatsOutsideUTC counts the calls in a file formatting a time layout, and
// names the ones whose receiver is not a call to UTC.
//
// A layout is a constant of the time package or a literal holding the
// reference year, which is how a layout is told from any other argument to a
// method called Format.
func formatsOutsideUTC(fset *token.FileSet, file *ast.File) (int, []string) {
	formats := 0
	var outside []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || method.Sel.Name != "Format" || !isTimeLayout(call.Args[0]) {
			return true
		}
		formats++
		if !isUTCCall(method.X) {
			outside = append(outside, fset.Position(call.Pos()).String())
		}
		return true
	})
	return formats, outside
}

func isTimeLayout(arg ast.Expr) bool {
	switch a := arg.(type) {
	case *ast.SelectorExpr:
		pkg, ok := a.X.(*ast.Ident)
		return ok && pkg.Name == "time"
	case *ast.BasicLit:
		if a.Kind != token.STRING {
			return false
		}
		layout, err := strconv.Unquote(a.Value)
		return err == nil && strings.Contains(layout, "2006")
	}
	return false
}

func isUTCCall(x ast.Expr) bool {
	call, ok := x.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "UTC"
}
