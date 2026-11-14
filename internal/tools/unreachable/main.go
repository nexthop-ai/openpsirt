// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command unreachable reports exported functions, methods, types, constants
// and variables that nothing outside their own declaration ever names.
//
// The static analysis gate reports unused *unexported* symbols and stops
// there, which leaves a whole class of defect invisible: a store method with
// no route to it, a renderer nothing renders with, a rule checked in a second
// place nothing reaches. Each of those looks like working code — the
// reasoning is sound, the tests pass, and none of it runs.
//
// A package-level declaration is counted by its package and its name. A
// qualified reference resolves through the file's imports, aliased and dot
// imports included, and a bare one counts toward the package it is written
// in, so a name two packages share does not hide an orphan in either.
//
// A method is counted by name alone, because telling which type a selector
// reaches needs type information. A method reached only through an interface
// counts as reached by name, which errs toward saying nothing: a check that
// accuses working code is a check somebody turns off. Where a struct field
// shares a method's name, only a call of that name counts, since a field read
// and a method value look alike without types.
//
// A declaration naming itself is not a use: a type is not reached by its own
// methods' receivers or its own fields, and a function is not reached by
// calling itself, nor a method by calling itself on its receiver. A field
// name or literal key of a struct declared in this repository is not a use of
// a method either; one of a struct from elsewhere is read as a use.
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
	"strconv"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// module is the import path prefix a package of this repository carries.
const module = "github.com/nexthop-ai/openpsirt"

// decl is one exported declaration. A method has an empty pkg, and is
// matched by name alone.
type decl struct {
	pkg  string
	name string
	file string
	line int
}

// key names a package-level symbol: the package it belongs to and its name.
type key struct{ pkg, name string }

// counts is how often each symbol is written anywhere. A package-level symbol
// nothing reaches is written exactly once, where it is declared; a method is
// counted by its uses alone, since several types may declare one name.
type counts struct {
	// symbols counts a package-level name under the package it resolves to.
	symbols map[key]int
	// names counts every use of a name, for methods.
	names map[string]int
	// calls counts every call of a name through a selector, for a method
	// whose name a struct field also carries.
	calls map[string]int
	// fields is every name a struct type declares as a field.
	fields map[string]bool
}

func newCounts() counts {
	return counts{symbols: map[key]int{}, names: map[string]int{}, calls: map[string]int{}, fields: map[string]bool{}}
}

// tally is what the walk has read: every exported declaration, and how often
// each name is written. The program and its tests read files through it, so
// the tests run the walk's own counting.
type tally struct {
	declared []decl
	seen     counts
}

func newTally() *tally {
	return &tally{seen: newCounts()}
}

// read takes in one parsed file.
func (t *tally) read(fset *token.FileSet, path string, file *ast.File) {
	t.declared = append(t.declared, declaredIn(fset, path, file)...)
	t.seen.add(path, file)
}

func main() {
	fset := token.NewFileSet()
	walked := newTally()

	// web holds the interface, which is TypeScript, and deploy, assets and
	// docs hold no Go either — but they are not named here, because reading a
	// directory with no Go in it costs nothing and a skip list is where a
	// gate quietly stops looking at part of the tree.
	read, err := walk.Sources(".go", func(path string, _ []byte) error {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		walked.read(fset, path, file)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	orphans, err := orphansOf(walked.declared, walked.seen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
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
	fmt.Printf("every exported symbol is named by something (%d in %d files)\n", len(walked.declared), read)
}

// packageOf is the package a file's bare identifiers belong to: its
// directory, or its directory marked apart for an external test package,
// whose bare names are its own rather than the package it tests.
func packageOf(path string, file *ast.File) string {
	dir := filepath.ToSlash(filepath.Dir(path))
	if strings.HasSuffix(file.Name.Name, "_test") {
		return dir + " (external test)"
	}
	return dir
}

// declaredIn is every exported declaration of one file. Test files and
// commands declare nothing another package can reach, so they declare
// nothing here.
func declaredIn(fset *token.FileSet, path string, file *ast.File) []decl {
	if strings.HasSuffix(path, "_test.go") || file.Name.Name == "main" {
		return nil
	}
	pkg := packageOf(path, file)
	var out []decl
	for _, d := range file.Decls {
		at := fset.Position(d.Pos())
		owner := pkg
		if f, ok := d.(*ast.FuncDecl); ok && f.Recv != nil {
			owner = ""
		}
		for _, name := range exportedIn(d) {
			out = append(out, decl{owner, name, at.Filename, at.Line})
		}
	}
	return out
}

// add counts every identifier one file writes.
//
// A selector whose left side names an import counts toward that package. A
// bare identifier counts toward the file's own package and toward each
// package the file dot-imports. Every identifier also counts by name, which
// is what a method is matched on.
//
// Each declaration's own name is counted once, as its declaration, and not
// again inside it: a recursive call, a type's reference to itself, and a
// method's receiver are the declaration naming itself.
func (c counts) add(path string, file *ast.File) {
	own := packageOf(path, file)
	imports := map[string]string{}
	var dotted []string
	for _, spec := range file.Imports {
		ipath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		dir, ours := directoryOf(ipath)
		if !ours {
			continue
		}
		switch {
		case spec.Name == nil:
			imports[importName(ipath)] = dir
		case spec.Name.Name == ".":
			dotted = append(dotted, dir)
		case spec.Name.Name != "_":
			imports[spec.Name.Name] = dir
		}
	}
	symbol := func(name string) {
		c.symbols[key{own, name}]++
		for _, dir := range dotted {
			c.symbols[key{dir, name}]++
		}
	}

	// self is the names the declaration being read declares, which it does
	// not use by writing; receiver and method are a method's receiver
	// variable and name, whose call on that receiver is the method calling
	// itself.
	var self map[string]bool
	var receiver, method string
	var visit func(ast.Node) bool
	inspect := func(n ast.Node) {
		if n != nil {
			ast.Inspect(n, visit)
		}
	}
	fieldTypes := func(list *ast.FieldList) {
		if list == nil {
			return
		}
		for _, field := range list.List {
			inspect(field.Type)
		}
	}
	visit = func(n ast.Node) bool {
		switch used := n.(type) {
		case *ast.StructType:
			// A field's name declares the field.
			for _, field := range used.Fields.List {
				for _, name := range field.Names {
					c.fields[name.Name] = true
				}
				inspect(field.Type)
			}
			return false
		case *ast.FuncType:
			// A parameter's or result's name declares a local.
			fieldTypes(used.TypeParams)
			fieldTypes(used.Params)
			fieldTypes(used.Results)
			return false
		case *ast.CallExpr:
			selector, ok := used.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := selector.X.(*ast.Ident); ok && method != "" &&
				x.Name == receiver && selector.Sel.Name == method {
				for _, argument := range used.Args {
					inspect(argument)
				}
				return false
			}
			c.calls[selector.Sel.Name]++
			return true
		case *ast.SelectorExpr:
			c.names[used.Sel.Name]++
			if x, ok := used.X.(*ast.Ident); ok {
				if dir, ok := imports[x.Name]; ok {
					c.symbols[key{dir, used.Sel.Name}]++
					return false
				}
			}
			inspect(used.X)
			return false
		case *ast.Ident:
			if self[used.Name] {
				return true
			}
			c.names[used.Name]++
			symbol(used.Name)
		}
		return true
	}

	for _, d := range file.Decls {
		self, receiver, method = nil, "", ""
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				symbol(d.Name.Name)
				self = map[string]bool{d.Name.Name: true}
			} else {
				// A method naming its own type, in its receiver, signature or
				// body, makes no use of it.
				method = d.Name.Name
				if len(d.Recv.List) > 0 && len(d.Recv.List[0].Names) > 0 {
					receiver = d.Recv.List[0].Names[0].Name
				}
				if len(d.Recv.List) > 0 {
					if own := receiverType(d.Recv.List[0].Type); own != "" {
						self = map[string]bool{own: true}
					}
				}
			}
			inspect(d.Type)
			inspect(d.Body)
		case *ast.GenDecl:
			if d.Tok == token.IMPORT {
				continue
			}
			for _, spec := range d.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					symbol(spec.Name.Name)
					self = map[string]bool{spec.Name.Name: true}
					fieldTypes(spec.TypeParams)
					inspect(spec.Type)
				case *ast.ValueSpec:
					self = map[string]bool{}
					for _, name := range spec.Names {
						symbol(name.Name)
						self[name.Name] = true
					}
					inspect(spec.Type)
					for _, value := range spec.Values {
						inspect(value)
					}
				}
			}
		}
	}
}

// directoryOf is the directory of a package of this repository, from its
// import path, and whether the path is one of ours at all.
func directoryOf(importPath string) (string, bool) {
	if importPath == module {
		return ".", true
	}
	rest, ok := strings.CutPrefix(importPath, module+"/")
	return rest, ok
}

// importName is the name an unaliased import binds: the last element of its
// path. Every package of this repository is named for its directory.
func importName(importPath string) string {
	return importPath[strings.LastIndex(importPath, "/")+1:]
}

// orphansOf is every declaration nothing but itself names, in file and line
// order. Reading no declaration at all is refused, since it would check
// nothing and report the same as a tree with no orphan.
func orphansOf(declared []decl, seen counts) ([]decl, error) {
	if len(declared) == 0 {
		return nil, fmt.Errorf("no exported declaration was read, so this checked nothing")
	}
	var orphans []decl
	for _, d := range declared {
		// A package-level symbol's count holds its declaration; a method's
		// holds its uses alone.
		used := seen.symbols[key{d.pkg, d.name}] > 1
		if d.pkg == "" {
			n := seen.names[d.name]
			if seen.fields[d.name] {
				n = seen.calls[d.name]
			}
			used = n > 0
		}
		if !used && !satisfiesSomething(d.name) {
			orphans = append(orphans, d)
		}
	}
	sort.Slice(orphans, func(i, j int) bool {
		if orphans[i].file != orphans[j].file {
			return orphans[i].file < orphans[j].file
		}
		return orphans[i].line < orphans[j].line
	})
	return orphans, nil
}

// exportedIn is every exported name one declaration makes.
//
// Types, values and constants as well as functions. A request type
// registered on no operation is fully specified and unreachable — in neither
// the OpenAPI document nor the generated client — and a type is the shape
// this gate is least able to be talked out of: it compiles, it reads as
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

// satisfiesSomething covers the names a standard interface calls, and the
// query hook's the database library calls, which are reached by the runtime
// or by that library rather than by anything written here.
func satisfiesSomething(name string) bool {
	switch name {
	case "Error", "String", "Unwrap", "Is", "As",
		"MarshalJSON", "UnmarshalJSON", "MarshalText", "UnmarshalText",
		"ServeHTTP", "Read", "Write", "Close", "Len", "Less", "Swap",
		"BeforeQuery", "AfterQuery":
		return true
	}
	return false
}

// receiverType is the name of the type a receiver is declared on, through a
// pointer and type parameters.
func receiverType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverType(t.X)
	case *ast.IndexExpr:
		return receiverType(t.X)
	case *ast.IndexListExpr:
		return receiverType(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}
