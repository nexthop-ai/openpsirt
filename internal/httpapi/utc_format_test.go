// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
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
// instead: a time layout passed to Format is formatted from a call to UTC, or
// from a local declared from one and never assigned again. A function keeping
// the offset on purpose is listed in keepsItsOffset with its reason.
//
// The source is every package of the server, under internal/ and cmd/,
// leaving out the programs that are not it: the repository's gates and the
// upload client, which formats on the machine of whoever runs it.
func TestEveryTimeTheServerFormatsIsFormattedInUTC(t *testing.T) {
	root := filepath.Join("..", "..")
	notTheServer := []string{
		filepath.Join(root, "internal", "tools"),
		filepath.Join(root, "internal", "uploadclient"),
		filepath.Join(root, "cmd", "openpsirt-upload"),
	}
	packages := map[string][]string{}
	for _, top := range []string{filepath.Join(root, "internal"), filepath.Join(root, "cmd")} {
		err := filepath.WalkDir(top, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || slices.Contains(notTheServer, path) {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				packages[filepath.Dir(path)] = append(packages[filepath.Dir(path)], path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	examined := 0
	kept := map[string]bool{}
	for _, paths := range packages {
		fset := token.NewFileSet()
		var files []*ast.File
		for _, path := range paths {
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, file)
		}
		layouts := layoutsDeclared(files)
		for _, file := range files {
			formats, outside := formatsOutsideUTC(file, layouts)
			examined += formats
			for _, at := range outside {
				if where := keptIn(fset, file, at); keepsItsOffset[where] != "" {
					kept[where] = true
					continue
				}
				t.Errorf("%s formats a time without converting it to UTC first", fset.Position(at))
			}
		}
	}
	if examined == 0 {
		t.Fatal("no time was formatted anywhere in the source, so this checked nothing")
	}
	for where := range keepsItsOffset {
		if !kept[where] {
			t.Errorf("%s keeps its offset here and formats nothing outside UTC", where)
		}
	}
}

// keepsItsOffset is each function formatting a time with its offset on
// purpose, as "package/file.go:function", with the reason. None of it is text
// anybody reads.
var keepsItsOffset = map[string]string{
	"finding/held.go:instantOf": "a key grouping findings by the moment written to the database, " +
		"which a moment with another offset is not",
}

// keptIn names the function holding a position in a file, as keepsItsOffset
// keys it, or empty outside every function.
func keptIn(fset *token.FileSet, file *ast.File, at token.Pos) string {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || at < fn.Pos() || at >= fn.End() {
			continue
		}
		name := fset.Position(fn.Pos()).Filename
		return filepath.Base(filepath.Dir(name)) + "/" + filepath.Base(name) + ":" + fn.Name.Name
	}
	return ""
}

// layoutsDeclared is every package-level string constant of these files
// holding the reference year, which a call names as a layout.
func layoutsDeclared(files []*ast.File) map[string]bool {
	layouts := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			group, ok := decl.(*ast.GenDecl)
			if !ok || group.Tok != token.CONST {
				continue
			}
			for _, spec := range group.Specs {
				value := spec.(*ast.ValueSpec)
				for i, name := range value.Names {
					if i < len(value.Values) && isTimeLayout(value.Values[i], nil) {
						layouts[name.Name] = true
					}
				}
			}
		}
	}
	return layouts
}

func TestTheUTCFormatGateTellsTheTwoShapesApart(t *testing.T) {
	const src = `package p

import "time"

const dayLayout = "2006-01-02"

const notALayout = "plain"

func f(at time.Time) (string, string, string, string, string) {
	return at.UTC().Format(time.DateOnly), at.Format(time.RFC3339), at.Format("2006-01-02"),
		at.Format(dayLayout), at.UTC().Format(dayLayout)
}

func h(at time.Time) (string, string) {
	when := at.UTC()
	moved := at.UTC()
	moved = at
	return when.Format(time.DateOnly), moved.Format(time.DateOnly)
}

var closure = func(at time.Time) string { when := at; return when.Format(time.DateOnly) }

func reused(at time.Time, all []time.Time) (string, string, string) {
	when := at.UTC()
	for _, when := range all {
		_ = when.Format(time.DateOnly)
	}
	echo := func(when time.Time) string { return when.Format(time.DateOnly) }
	return when.Format(time.DateOnly), echo(at), ""
}

func g(v value) string { return v.Format(notALayout) }

`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	formats, outside := formatsOutsideUTC(file, layoutsDeclared([]*ast.File{file}))
	if formats != 11 || len(outside) != 8 {
		t.Errorf("read %d formats and %d outside UTC (%v), want 11 and the eight without a conversion: "+
			"a local held from UTC is converted, one assigned or bound again or in another declaration is not",
			formats, len(outside), outside)
	}
	if len(outside) > 0 {
		if got := keptIn(fset, file, outside[0]); got != "./p.go:f" {
			t.Errorf("a format inside f is held by %q", got)
		}
	}
	if got := keptIn(fset, file, file.Package); got != "" {
		t.Errorf("a position outside every function is held by %q", got)
	}
}

// formatsOutsideUTC counts the calls in a file formatting a time layout, and
// returns where the ones whose receiver is not a call to UTC are.
//
// A layout is a constant of the time package, a literal holding the reference
// year, or a constant of the package declared as one, which is how a layout is
// told from any other argument to a method called Format.
func formatsOutsideUTC(file *ast.File, layouts map[string]bool) (int, []token.Pos) {
	formats := 0
	var outside []token.Pos
	for _, decl := range file.Decls {
		held := heldInUTC(decl)
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || method.Sel.Name != "Format" || !isTimeLayout(call.Args[0], layouts) {
				return true
			}
			formats++
			if !isUTCCall(method.X) && !isHeld(method.X, held) {
				outside = append(outside, call.Pos())
			}
			return true
		})
	}
	return formats, outside
}

func isTimeLayout(arg ast.Expr, layouts map[string]bool) bool {
	switch a := arg.(type) {
	case *ast.Ident:
		return layouts[a.Name]
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

// heldInUTC is every name a function declares from a call to UTC and never
// assigns or binds again, so formatting it formats a UTC time. Names are read within
// one top-level declaration, where a local's name is its own.
func heldInUTC(body ast.Node) map[string]bool {
	held := map[string]bool{}
	moved := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		// A name bound any other way, by a range, a parameter or a var, is
		// another value under the same name, so the name is held nowhere in
		// the declaration.
		switch other := n.(type) {
		case *ast.RangeStmt:
			for _, bound := range []ast.Expr{other.Key, other.Value} {
				if id, ok := bound.(*ast.Ident); ok {
					moved[id.Name] = true
				}
			}
		case *ast.Field:
			for _, id := range other.Names {
				moved[id.Name] = true
			}
		case *ast.ValueSpec:
			for _, id := range other.Names {
				moved[id.Name] = true
			}
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			if assign.Tok == token.DEFINE && len(assign.Rhs) == len(assign.Lhs) &&
				isUTCCall(assign.Rhs[i]) && !held[id.Name] {
				held[id.Name] = true
				continue
			}
			moved[id.Name] = true
		}
		return true
	})
	for name := range moved {
		delete(held, name)
	}
	return held
}

func isHeld(x ast.Expr, held map[string]bool) bool {
	id, ok := x.(*ast.Ident)
	return ok && held[id.Name]
}

func isUTCCall(x ast.Expr) bool {
	call, ok := x.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "UTC"
}
