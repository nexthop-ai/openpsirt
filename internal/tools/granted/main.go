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
// tag and the query never spells it. The rule is applied per function, because
// a file holding one query of each kind names both tables while each query
// names one.
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

// The two tables a role is held in, and the models bound to them.
const (
	perProduct      = "role_grant"
	estate          = "role_grant_all"
	perProductModel = "Grant"
	estateModel     = "EstateGrant"
	accessPackage   = "access"
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
	"internal/access/store.go:GrantRole":           "records a grant on one product, which is one row of that table",
	"internal/access/store.go:holds": "whether a per-product grant that failed to insert is already there, " +
		"which is a question about that row; an estate grant does not make it a duplicate",
	"internal/access/store.go:People":   "lists what everybody holds per product, beside EveryEstateGrant",
	"internal/access/store.go:Grants":   "lists what one person holds per product, beside EstateGrants",
	"internal/access/store.go:Withdraw": "withdraws a grant on one product, which is one row of that table",
	"internal/access/binding.go:replaceDerived": "rewrites the grants a person's groups give, which are " +
		"roles on products: a group grants nothing across the estate",
}

// reach is which grant tables a piece of source reaches.
type reach struct{ perProduct, estate bool }

// reached reports which grant tables a node reaches: by a table's name in a
// string, by the model bound to it, or by a package-level name in `names`
// whose declaration reaches one. Inside the access package the model is a bare
// name; elsewhere it is qualified by the package.
func reached(n ast.Node, inAccess bool, names map[string]reach) reach {
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
			if pkg, ok := n.X.(*ast.Ident); ok && pkg.Name == accessPackage {
				r.model(n.Sel.Name)
			}
			// A field or method of that name on something else is not the
			// model, so the selected name is not visited on its own.
			r = r.or(reached(n.X, inAccess, names))
			return false
		case *ast.Ident:
			if inAccess {
				r.model(n.Name)
			}
			r = r.or(names[n.Name])
		}
		return true
	})
	return r
}

func (r *reach) model(name string) {
	switch name {
	case perProductModel:
		r.perProduct = true
	case estateModel:
		r.estate = true
	}
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

// declared is the reach of every package-level constant and variable a file
// declares, by name. Each name is judged by its own value, so a block holding
// one query per grant table is two names that each reach one.
func declared(file *ast.File, inAccess bool) map[string]reach {
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
					r = reached(value.Values[i], inAccess, nil)
				}
				if value.Type != nil {
					r = r.or(reached(value.Type, inAccess, nil))
				}
				names[name.Name] = names[name.Name].or(r)
			}
		}
	}
	return names
}

// oneAlone is every function or package-level name in a file that reaches one
// grant table and not the other, with the table it leaves out.
//
// A function reaches what its body names, including the package-level names
// it uses: `pkg` holds those of the file's package, and where it is nil the
// file's own are read. A package-level name is reported by itself, since a
// name reaching one table is a query that asks one.
//
// Lifted out of the walk so it can be asked directly: a gate reachable only by
// running the program over the tree has an exit code for its only evidence.
func oneAlone(path string, src []byte, pkg map[string]reach) (map[string]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		return nil, err
	}
	inAccess := file.Name.Name == accessPackage
	own := declared(file, inAccess)
	if pkg == nil {
		pkg = own
	}
	found := map[string]string{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if table, only := reached(fn.Body, inAccess, pkg).missing(); only {
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

// packageNames is the reach of every package-level name each directory's
// files declare, tests aside.
func packageNames() (map[string]map[string]reach, error) {
	byDir := map[string]map[string]reach{}
	_, err := walk.Only(".go", []string{"web"}, func(path string, text []byte) error {
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, text, 0)
		if err != nil {
			return err
		}
		dir := filepath.Dir(path)
		if byDir[dir] == nil {
			byDir[dir] = map[string]reach{}
		}
		for name, r := range declared(file, file.Name.Name == accessPackage) {
			byDir[dir][name] = byDir[dir][name].or(r)
		}
		return nil
	})
	return byDir, err
}

func main() {
	var bad []string
	used := map[string]bool{}
	names, err := packageNames()
	if err != nil {
		fmt.Fprintln(os.Stderr, "granted:", err)
		os.Exit(1)
	}
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
		pkg := names[filepath.Dir(path)]
		if pkg == nil {
			pkg = map[string]reach{}
		}
		found, err := oneAlone(path, text, pkg)
		if err != nil {
			return err
		}
		for name, table := range found {
			key := path + ":" + name
			if _, named := inside[key]; named {
				used[key] = true
				continue
			}
			bad = append(bad, fmt.Sprintf("%s: reaches one grant table and not %s", key, table))
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "granted:", err)
		os.Exit(1)
	}
	// An exemption nothing matches is one a rename left behind, and a function
	// of that name added later would be waved through unread.
	for key := range inside {
		if !used[key] {
			bad = append(bad, fmt.Sprintf("%s: named as reaching one table alone, and nothing there does", key))
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
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
