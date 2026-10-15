// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command granted reports a query that asks one grant table and not the other.
//
// A role is held two ways: against one product, and across every product. What
// somebody may do is worked out where those two are resolved together, so every
// check that goes through a subject sees both for free — which is why the roles
// are spread into one map as a subject is built rather than carried as a flag
// into every query.
//
// A query that reaches a grant table directly bypasses that. One that asks the
// per-product table alone refuses a finding to somebody handed it across the
// estate, releases work from somebody who can still open it, omits them from
// who may be mentioned, and reports every approval an estate approver gave as
// lapsed. None of those is wrong about anything it asks — each asks one table.
//
// So the rule is not "do not name a grant table" but "name both". A function
// that reaches one and not the other is a predicate that cannot see half of
// what somebody holds, and nothing else in the tree notices: it compiles, it
// passes, and it answers no.
//
// A table is reached two ways, and both are read: by its name in a string, and
// by the model a query is built from, since a model binds its table in a struct
// tag and the query never spells it. A model is recognized by that tag, under
// whatever name it is declared and whatever name its package is imported as,
// and so is a type built from one: an alias of it, or a struct embedding it.
// The rule is applied per function, because a file holding one query of each
// kind names both tables while each query names one.
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

// The two tables a role is held in.
const (
	perProduct = "role_grant"
	estate     = "role_grant_all"
)

// allowed is where one may be named alone, and why.
var allowed = []string{
	// The schema, which creates them.
	"internal/database/migrate/",
	// The test harness, which names every table in order to empty them.
	"internal/dbtest/",
	// This program, which names both in order to look for them.
	"internal/tools/granted/",
}

// inside is each function that may reach one table alone, and why. Keyed by
// file and function, so a new query beside one of these is still checked.
var inside = map[string]string{
	"internal/access/estate.go:GrantEstateRole": "records a grant across the estate, and its duplicate check " +
		"is about an estate row: holding a role on one product does not make one covering all of them a duplicate",
	"internal/access/estate.go:WithdrawEstateRole": "withdraws a grant across the estate, which is one row of that table",
	"internal/access/estate.go:EstateGrants":       "lists what one person holds across the estate, beside Grants",
	"internal/access/estate.go:EveryEstateGrant":   "lists what everybody holds across the estate, beside People",
	"internal/access/grants.go:GrantRole":          "records a grant on one product, which is one row of that table",
	"internal/access/grants.go:holds": "whether a per-product grant that failed to insert is already there, " +
		"which is a question about that row; an estate grant does not make it a duplicate",
	"internal/access/grants.go:People":   "lists what everybody holds per product, beside EveryEstateGrant",
	"internal/access/grants.go:Grants":   "lists what one person holds per product, beside EstateGrants",
	"internal/access/grants.go:Withdraw": "withdraws a grant on one product, which is one row of that table",
}

// reach is which grant tables a piece of source reaches.
type reach struct{ perProduct, estate bool }

// models is the reach of every type each package declares, by import path and
// type name. A model binds its table in a struct tag, so a type whose
// declaration names a grant table is a model of it, whatever it is called.
type models map[string]map[string]reach

// scope is what a name in one file can mean: a package-level name or type of
// its own package, or a type of a package it imports under some name.
type scope struct {
	names   map[string]reach
	imports map[string]map[string]reach
}

// reached reports which grant tables a node reaches: by a table's name in a
// string, by a type whose declaration names one, or by a package-level name
// whose declaration reaches one.
func reached(n ast.Node, in scope) reach {
	var r reach
	ast.Inspect(n, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BasicLit:
			if n.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(n.Value)
			if err != nil {
				text = n.Value
			}
			if strings.Contains(text, estate) {
				r.estate = true
			}
			if strings.Contains(strings.ReplaceAll(text, estate, ""), perProduct) {
				r.perProduct = true
			}
		case *ast.SelectorExpr:
			if pkg, ok := n.X.(*ast.Ident); ok {
				r = r.or(in.imports[pkg.Name][n.Sel.Name])
			}
			// A field or method of that name on something else is not the
			// model, so the selected name is not visited on its own.
			r = r.or(reached(n.X, in))
			return false
		case *ast.Ident:
			r = r.or(in.names[n.Name])
		}
		return true
	})
	return r
}

func (r reach) or(other reach) reach {
	return reach{r.perProduct || other.perProduct, r.estate || other.estate}
}

// missing is the table a reach leaves out, where it reaches only one.
func (r reach) missing() (string, bool) {
	switch {
	case r.perProduct == r.estate:
		return "", false
	case r.estate:
		return perProduct, true
	default:
		return estate, true
	}
}

// typesIn is the reach of every type a file declares, by name. Struct tags are
// strings, so a model's `table:` tag is read the way any other string is.
//
// A type built from a model takes on its reach: an alias or a definition from
// it, `type row = access.Grant`, and a struct embedding it, which is how bun
// extends a model. Those names are resolved in scope, which is the file's
// package's types and the types of what it imports, so a caller reaches a
// fixed point by asking again with what this answered until nothing grows. A
// named field holding a model is not a model, because a query built from the
// struct does not select from the field's table.
func typesIn(file *ast.File, in scope) map[string]reach {
	types := map[string]reach{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			if typ, ok := spec.(*ast.TypeSpec); ok {
				r := reached(typ.Type, scope{}).or(builtFrom(typ.Type, in))
				types[typ.Name.Name] = types[typ.Name.Name].or(r)
			}
		}
	}
	return types
}

// builtFrom is the reach of the types a type expression is built from: the
// type it names, and the types a struct embeds.
func builtFrom(expr ast.Expr, in scope) reach {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return builtFrom(e.X, in)
	case *ast.Ident:
		return in.names[e.Name]
	case *ast.SelectorExpr:
		if pkg, ok := e.X.(*ast.Ident); ok {
			return in.imports[pkg.Name][e.Sel.Name]
		}
	case *ast.StructType:
		var r reach
		for _, field := range e.Fields.List {
			if len(field.Names) == 0 {
				r = r.or(builtFrom(field.Type, in))
			}
		}
		return r
	}
	return reach{}
}

// grown reports whether b reaches anything a does not.
func grown(a, b map[string]reach) bool {
	for name, r := range b {
		if a[name].or(r) != a[name] {
			return true
		}
	}
	return false
}

// declared is the reach of every package-level constant and variable a file
// declares, by name. Each name is judged by its own value, so a block holding
// one query per grant table is two names that each reach one.
func declared(file *ast.File, in scope) map[string]reach {
	names := map[string]reach{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok == token.TYPE || gen.Tok == token.IMPORT {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				var r reach
				if i < len(value.Values) {
					r = reached(value.Values[i], in)
				}
				if value.Type != nil {
					r = r.or(reached(value.Type, in))
				}
				names[name.Name] = names[name.Name].or(r)
			}
		}
	}
	return names
}

// imported is the types of each package a file imports, by the name the file
// calls it. An import with no name of its own is called by the package's
// declared name, which `packages` holds, or failing that its last element.
func imported(file *ast.File, types models, packages map[string]string) map[string]map[string]reach {
	byName := map[string]map[string]reach{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := packages[path]
		if name == "" {
			name = path[strings.LastIndex(path, "/")+1:]
		}
		if spec.Name != nil {
			name = spec.Name.Name
		}
		byName[name] = types[path]
	}
	return byName
}

// merged is two maps of reaches as one.
func merged(a, b map[string]reach) map[string]reach {
	out := map[string]reach{}
	for name, r := range a {
		out[name] = r
	}
	for name, r := range b {
		out[name] = out[name].or(r)
	}
	return out
}

// tree is what the walk learns about the whole tree before any function is
// judged: each directory's package-level names and types, each package's
// types by import path, and each import path's declared package name.
type tree struct {
	names    map[string]map[string]reach
	types    models
	packages map[string]string
}

// oneAlone is every function or package-level name in a file that reaches one
// grant table and not the other, with the table it leaves out.
//
// A function reaches what its body names, including the package-level names
// and types it uses: `pkg` holds those of the file's package, and where it is
// nil the file's own are read. `types` holds the types of every package the
// file may import. A package-level name is reported by itself, since a name
// reaching one table is a query that asks one; a type is not, since a model
// declares a table rather than asking it.
//
// Lifted out of the walk so it can be asked directly: a gate reachable only by
// running the program over the tree has an exit code for its only evidence.
func oneAlone(path string, src []byte, pkg map[string]reach, types models, packages map[string]string) (map[string]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		return nil, err
	}
	imports := imported(file, types, packages)
	local := typesIn(file, scope{imports: imports})
	for {
		next := merged(local, typesIn(file, scope{names: local, imports: imports}))
		if !grown(local, next) {
			break
		}
		local = next
	}
	own := declared(file, scope{names: local, imports: imports})
	if pkg == nil {
		pkg = merged(own, local)
	}
	in := scope{names: pkg, imports: imports}
	found := map[string]string{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if table, only := reached(fn.Body, in).missing(); only {
			found[fn.Name.Name] = table
		}
	}
	for name, r := range own {
		if table, only := r.missing(); only {
			found[name] = table
		}
	}
	return found, nil
}

// learn reads the whole tree, tests aside, for what `tree` holds. A file's
// package-level names are judged with its own package's types and the types of
// what it imports, so types are read in passes of their own first.
func learn(module string) (tree, error) {
	t := tree{names: map[string]map[string]reach{}, types: models{}, packages: map[string]string{}}
	files := map[string]*ast.File{}
	_, err := walk.Only(".go", []string{"web"}, func(path string, text []byte) error {
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, text, 0)
		if err != nil {
			return err
		}
		files[path] = file
		importPath := module + "/" + filepath.ToSlash(filepath.Dir(path))
		t.packages[importPath] = file.Name.Name
		t.types[importPath] = merged(t.types[importPath], typesIn(file, scope{}))
		return nil
	})
	if err != nil {
		return t, err
	}
	// A type built from a model in another package needs that package's types
	// first, in whatever order the walk read them, so the passes repeat until
	// no type reaches anything new.
	for changed := true; changed; {
		changed = false
		for path, file := range files {
			importPath := module + "/" + filepath.ToSlash(filepath.Dir(path))
			in := scope{names: t.types[importPath], imports: imported(file, t.types, t.packages)}
			if next := typesIn(file, in); grown(t.types[importPath], next) {
				t.types[importPath] = merged(t.types[importPath], next)
				changed = true
			}
		}
	}
	for path, file := range files {
		dir := filepath.Dir(path)
		importPath := module + "/" + filepath.ToSlash(dir)
		in := scope{names: t.types[importPath], imports: imported(file, t.types, t.packages)}
		t.names[dir] = merged(t.names[dir], declared(file, in))
	}
	for path := range files {
		dir := filepath.Dir(path)
		t.names[dir] = merged(t.names[dir], t.types[module+"/"+filepath.ToSlash(dir)])
	}
	return t, nil
}

// moduleOf is the module path go.mod in the working directory declares.
func moduleOf() (string, error) {
	text, err := os.ReadFile("go.mod")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(text), "\n") {
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("go.mod declares no module")
}

// verdict is what the gate reports from every function found reaching one
// table alone, keyed by file and function, against the exemptions. An
// exemption nothing matches is one a rename left behind, and a function of
// that name added later would be waved through unread.
func verdict(found map[string]string, exempt map[string]string) []string {
	var bad []string
	for key, table := range found {
		if _, named := exempt[key]; !named {
			bad = append(bad, fmt.Sprintf("%s: reaches one grant table and not %s", key, table))
		}
	}
	for key := range exempt {
		if _, there := found[key]; !there {
			bad = append(bad, fmt.Sprintf("%s: named as reaching one table alone, and nothing there does", key))
		}
	}
	sort.Strings(bad)
	return bad
}

func main() {
	module, err := moduleOf()
	if err != nil {
		fmt.Fprintln(os.Stderr, "granted:", err)
		os.Exit(1)
	}
	known, err := learn(module)
	if err != nil {
		fmt.Fprintln(os.Stderr, "granted:", err)
		os.Exit(1)
	}
	found := map[string]string{}
	// web holds the interface, which reaches no table: it asks this server.
	read, err := walk.Only(".go", []string{"web"}, func(path string, text []byte) error {
		// A test may assert about one table on purpose: it is saying what is
		// in a row rather than deciding what somebody may reach.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, where := range allowed {
			if strings.HasPrefix(path, where) {
				return nil
			}
		}
		pkg := known.names[filepath.Dir(path)]
		if pkg == nil {
			pkg = map[string]reach{}
		}
		names, err := oneAlone(path, text, pkg, known.types, known.packages)
		if err != nil {
			return err
		}
		for name, table := range names {
			found[path+":"+name] = table
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "granted:", err)
		os.Exit(1)
	}
	if read == 0 {
		fmt.Fprintln(os.Stderr, "granted: no Go file was read, so this checked nothing")
		os.Exit(2)
	}
	if bad := verdict(found, inside); len(bad) > 0 {
		fmt.Fprintln(os.Stderr,
			"these ask one grant table and not the other, so they cannot see a role held\n"+
				"across every product. Ask both, resolve what somebody holds through a subject,\n"+
				"or name the function in this gate with the reason it asks one:")
		for _, line := range bad {
			fmt.Fprintln(os.Stderr, "  "+line)
		}
		os.Exit(1)
	}
	fmt.Printf("every query asks both grant tables, beside the %d named for asking "+
		"one (%d files checked)\n", len(inside), read)
}
