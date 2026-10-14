// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command narrowed reports a build resolved for a case collaborator whose
// names then reach a read that carries no subject.
//
// Somebody invited onto one embargoed issue holds nothing on the product. The
// resolver that turns three names into a build admits them anyway, and
// deliberately: what they were told already names the product, so refusing to
// resolve it would refuse them the one thing they were granted while telling
// them nothing they did not already know. What makes that safe is the sentence
// beside it — every read past this asks about the issue again.
//
// A read that follows the resolution and checks only whether one issue is
// undisclosed, never whether the subject can read the product at all, hands a
// collaborator on one embargoed issue every approved statement for the whole
// build. A route that re-checks and one that does not look alike: both
// compile, pass and answer.
//
// So the rule this holds to is the one the requirements already state — a read
// carries a subject and is narrowed in the data layer, never in a handler. A
// name resolved this way may be used to ask something that carries the
// subject, or to resolve an address further; it may not be handed to a read
// that does not.
//
// The names, and the address resolved from them. A build resolved this way
// is almost never read directly: it is handed to the call that turns a release
// and a variant into a build, and the finding query is keyed on what that
// returned. So what a resolver hands back is followed as another name, and so
// is whatever a route copies, collects or builds a value from with it, however
// many hops away, whether bound by an assignment or by `var`. A use is the
// name itself handed on as well as a field read off it, and the call that
// decides is the innermost one around the use. Anything further — a
// resolution used inline without being bound, or a value carried out of the
// function and back — is not followed, because a gate that did would be an
// analysis rather than a check. What it buys is that the next call site
// arrives announced rather than discovered.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// permissive are the two resolvers a case grant satisfies: the catalog's own,
// and the handler helper that wraps it.
var permissive = map[string]bool{
	"LocateVisible":  true,
	"LocatedVisibly": true,
}

// subjectNamed is what the subject is called wherever it is carried. One name
// tree-wide, which is what lets this ask whether a call carries it.
const subjectNamed = "subject"

// resolving are calls that turn part of an address into another part of the
// same address. They answer nothing about findings, so they need no subject:
// what they return is the pair of names that was already resolved.
var resolving = map[string]string{
	"TargetFor":      "the build a release and a variant name",
	"ExistingTarget": "the same, refusing one nothing has been filed against",
	"TargetRow":      "the same, with the refusal a route answers",
	"Describe":       "how a build is spelled on screen",
	"ComponentAs":    "which component in that build a name stands for, at a stated version",
	"ComponentAsIn":  "the same, refused where the name is held twice",
	"append":         "collecting resolved builds to ask about together",
}

// A resolver's answer stands for the same permissive resolution and is
// followed as another name, which is what makes this check reach the read: at
// nearly every site the one visible use of the resolved names is the resolver
// call, and the finding query is keyed on what it returned.

// unnarrowed is one use of a resolved build that carries no subject.
type unnarrowed struct {
	at   string
	name string
}

func main() {
	var bad []unnarrowed
	sites, derived := 0, 0
	// web is the interface, which reaches no database: it asks this server.
	read, err := walk.Only(".go", []string{"web"}, func(path string, body []byte) error {
		// A test resolves a build in order to set one up, and asserts about
		// rows rather than deciding what anybody may reach.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, body, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		// closures is where the closures are, so that a resolution
		// inside one is checked against the closure that holds it
		// rather than twice: a route's handler is a closure inside the
		// function that registers it, and the refusal that covers it
		// stands in the closure.
		var closures []*ast.FuncLit
		ast.Inspect(file, func(node ast.Node) bool {
			if lit, ok := node.(*ast.FuncLit); ok {
				closures = append(closures, lit)
			}
			return true
		})
		ast.Inspect(file, func(node ast.Node) bool {
			body := functionBody(node)
			if body == nil {
				return true
			}
			resolved := resolvedOutside(body, closures)
			loose, held, followed := looseIn(body, resolved)
			sites += held
			derived += followed
			for name, uses := range loose {
				for _, use := range uses {
					bad = append(bad, unnarrowed{
						at: fmt.Sprintf("%s:%d", path, fset.Position(use).Line),
						name: fmt.Sprintf("%s, resolved at line %d",
							name, fset.Position(resolved[name]).Line),
					})
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "narrowed:", err)
		os.Exit(1)
	}
	if sites == 0 {
		fmt.Fprintln(os.Stderr,
			"narrowed: nothing resolves a build for a case collaborator, so this checked nothing")
		os.Exit(1)
	}
	if len(bad) > 0 {
		fmt.Fprintln(os.Stderr,
			"these hand a build resolved for a case collaborator to something that carries no\n"+
				"subject, so a collaborator on one issue is answered about the whole product:")
		for _, one := range bad {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", one.at, one.name)
		}
		os.Exit(1)
	}
	fmt.Printf("every build resolved for a case collaborator is read with a subject "+
		"(%d resolutions and %d addresses resolved from them, in %d files)\n",
		sites, derived, read)
}

// resolvedOutside is resolvedIn for what this function holds directly.
// Anything inside a closure is checked when the walk reaches that closure. A
// name bound more than once is kept while any of its bindings is this
// function's own: a closure rebinding it does not take the outer resolution
// away.
func resolvedOutside(body *ast.BlockStmt, closures []*ast.FuncLit) map[string]token.Pos {
	inner := func(at token.Pos) bool {
		for _, lit := range closures {
			if lit.Body == body {
				continue
			}
			if lit.Pos() < at && at < lit.End() &&
				body.Pos() < lit.Pos() && lit.End() < body.End() {
				return true
			}
		}
		return false
	}
	resolved := map[string]token.Pos{}
	for name, positions := range resolvedIn(body) {
		for _, at := range positions {
			if !inner(at) {
				resolved[name] = at
				break
			}
		}
	}
	return resolved
}

// looseIn is every use of a resolved build in this function that nothing
// narrows, with how many resolutions were held and how many addresses were
// followed from them.
//
// One function rather than three called in order, because what it decides is
// one question — is this read narrowed — and the parts only mean anything
// together: a refusal exempts the whole function, and a name a resolver handed
// back stands for the build that was resolved.
func looseIn(body *ast.BlockStmt, resolved map[string]token.Pos) (map[string][]token.Pos, int, int) {
	held := len(resolved)
	followed := 0
	// The values the address resolvers handed back, which is where nearly every
	// site does its reading.
	for name, from := range derivedIn(body, resolved) {
		if _, already := resolved[name]; !already {
			resolved[name] = from
			followed++
		}
	}
	loose := map[string][]token.Pos{}
	if held == 0 {
		return loose, held, followed
	}
	// A refusal covers what comes after it, so a use before it is still a
	// read nothing narrowed. A use before the name was bound from the build
	// is of some earlier value under the same name.
	refusal := refusedAt(body, resolved)
	for name, bound := range resolved {
		var uses []token.Pos
		for _, use := range unguarded(body, name) {
			if use < bound {
				continue
			}
			if !refusal.IsValid() || use < refusal {
				uses = append(uses, use)
			}
		}
		if len(uses) > 0 {
			loose[name] = uses
		}
	}
	return loose, held, followed
}

// functionBody is the body of a declared function or of a closure.
//
// Both, because a route's handler is a closure inside the function that
// registers it, and that is where most of these resolutions happen.
func functionBody(node ast.Node) *ast.BlockStmt {
	switch fn := node.(type) {
	case *ast.FuncDecl:
		return fn.Body
	case *ast.FuncLit:
		return fn.Body
	}
	return nil
}

// resolvedIn returns what each permissive resolution in this body was bound
// to, and where.
//
// The whole body rather than its own statement list: a resolution inside a
// loop over the builds a request names, or inside the branch that handles one
// of two shapes, is a resolution like any other — and reading only the top
// level made three of them invisible, two of which arrived in the change that
// added this program.
//
// Every binding of a name, because a closure may bind the same name again and
// the last binding read alone would decide the outer one away.
func resolvedIn(body *ast.BlockStmt) map[string][]token.Pos {
	found := map[string][]token.Pos{}
	ast.Inspect(body, func(node ast.Node) bool {
		name, call, at, ok := binding(node)
		if !ok || !permissive[called(call)] {
			return true
		}
		found[name] = append(found[name], at)
		return true
	})
	return found
}

// binding is the name a call's first result is bound to, in either spelling a
// function body binds one: an assignment, or a declaration with `var`.
func binding(node ast.Node) (name string, call *ast.CallExpr, at token.Pos, ok bool) {
	var lhs, rhs []ast.Expr
	switch bound := node.(type) {
	case *ast.AssignStmt:
		lhs, rhs, at = bound.Lhs, bound.Rhs, bound.Pos()
	case *ast.ValueSpec:
		for _, n := range bound.Names {
			lhs = append(lhs, n)
		}
		rhs, at = bound.Values, bound.Pos()
	default:
		return "", nil, 0, false
	}
	if len(rhs) != 1 || len(lhs) == 0 {
		return "", nil, 0, false
	}
	call, isCall := rhs[0].(*ast.CallExpr)
	first, isName := lhs[0].(*ast.Ident)
	if !isCall || !isName || first.Name == "_" {
		return "", nil, 0, false
	}
	return first.Name, call, at, true
}

// derivedIn returns every name bound from the names already resolved, followed
// to a fixed point.
//
// The hop that consumed the check. Almost every site hands the resolved
// names straight to one of the address resolvers and then reads through what
// that returned, so the one use this program could see was the exempt one and
// there was nothing left to check. The build a resolver hands back stands for
// the same permissive resolution, so it is followed as another name; so is a
// value copied or collected from one, however many hops away.
//
// A call carrying the subject is where a resolved build is narrowed, so what
// it returns is not followed. Nor is a call's error, which says whether it
// answered rather than what it answered about.
func derivedIn(body *ast.BlockStmt, from map[string]token.Pos) map[string]token.Pos {
	known := map[string]token.Pos{}
	for name, at := range from {
		known[name] = at
	}
	found := map[string]token.Pos{}
	for grew := true; grew; {
		grew = false
		ast.Inspect(body, func(node ast.Node) bool {
			for _, bound := range bindings(node) {
				if _, already := known[bound.name]; already || !mentions(bound.from, known) {
					continue
				}
				if call, isCall := bound.from.(*ast.CallExpr); isCall && carriesSubject(call) {
					continue
				}
				known[bound.name], found[bound.name] = bound.at, bound.at
				grew = true
			}
			return true
		})
	}
	return found
}

// bound is one name and the value it is bound from.
type bound struct {
	name string
	from ast.Expr
	at   token.Pos
}

// bindings is each name an assignment or a declaration binds, paired with the
// value it is bound from: one for one where both sides list as many, and the
// first name alone where one call answers several, since the rest are what a
// call says about its own answer. Names bound to `_` are left out.
func bindings(node ast.Node) []bound {
	var lhs, rhs []ast.Expr
	var at token.Pos
	switch b := node.(type) {
	case *ast.AssignStmt:
		lhs, rhs, at = b.Lhs, b.Rhs, b.Pos()
	case *ast.ValueSpec:
		for _, n := range b.Names {
			lhs = append(lhs, n)
		}
		rhs, at = b.Values, b.Pos()
	default:
		return nil
	}
	var out []bound
	pair := func(left, right ast.Expr) {
		if named, isName := left.(*ast.Ident); isName && named.Name != "_" {
			out = append(out, bound{name: named.Name, from: right, at: at})
		}
	}
	switch {
	case len(lhs) == len(rhs):
		for i := range lhs {
			pair(lhs[i], rhs[i])
		}
	case len(rhs) == 1 && len(lhs) > 0:
		pair(lhs[0], rhs[0])
	}
	return out
}

// mentions reports whether an expression reads one of these names.
func mentions(expr ast.Node, names map[string]token.Pos) bool {
	seen := false
	ast.Inspect(expr, func(node ast.Node) bool {
		base, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		if _, held := names[base.Name]; held {
			seen = true
		}
		return true
	})
	return seen
}

// called is the name of the function a call names, without its receiver.
func called(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// unguarded finds every use of a resolved build that no call carrying the
// subject covers.
//
// A use is the name read: a field of it, or the name itself handed on. The
// call that decides is the innermost one around the use, because that is the
// call the value reaches. A subject carried by a call further out is carried
// to that call, not to whatever the inner one did with the build first.
func unguarded(body *ast.BlockStmt, name string) []token.Pos {
	var loose []token.Pos
	// path is where the walk currently is. Every node is pushed on the way
	// in and popped on the way out, which is the only way this stays a
	// stack: the walk announces the end of a node by handing over nothing,
	// whatever kind of node it was, so pushing one kind and popping on
	// every ending empties it immediately — and an empty stack reads here
	// as "used outside a call", which is the answer that passes.
	var path []ast.Node
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			path = path[:len(path)-1]
			return true
		}
		path = append(path, node)

		used, ok := node.(*ast.Ident)
		if !ok || used.Name != name || len(path) < 2 {
			return true
		}
		// The name as a selector's field, or as the key of a composite
		// literal, is some other thing's name.
		if selector, ok := path[len(path)-2].(*ast.SelectorExpr); ok && selector.Sel == used {
			return true
		}
		if pair, ok := path[len(path)-2].(*ast.KeyValueExpr); ok && pair.Key == used {
			return true
		}
		for i := len(path) - 2; i >= 0; i-- {
			call, ok := path[i].(*ast.CallExpr)
			if !ok {
				continue
			}
			// A conversion hands the value on unchanged, so the call that
			// decides is the one around it.
			if converts(call) {
				continue
			}
			if carriesSubject(call) {
				return true
			}
			if _, address := resolving[called(call)]; address {
				return true
			}
			// Returned rather than read where no call holds it: a resolver
			// hands the names back, and its own callers are checked here
			// too.
			loose = append(loose, used.Pos())
			return true
		}
		return true
	})
	return loose
}

// converts reports whether a call is a conversion to a basic type, which hands
// its argument on rather than reading it.
func converts(call *ast.CallExpr) bool {
	named, ok := call.Fun.(*ast.Ident)
	if !ok || len(call.Args) != 1 {
		return false
	}
	switch named.Name {
	case "int", "int32", "int64", "uint", "uint32", "uint64", "string":
		return true
	}
	return false
}

// refusedAt finds where the function asks the subject about the build it just
// resolved, and turns them away.
//
// The test is deliberately narrow: the refusal stands in the function's own
// statement list, so that it covers everything after it, and a use before it
// is still reported. A check of the same shape nested inside another condition
// covers only what that condition covers, which is how a collaborator received a whole build's approved
// statements — the only subject question on that path was reached when the
// caller asked for undisclosed work, and a caller asking for what is published
// went past it.
//
// It answers where the first refusal stands, and token.NoPos where none does.
func refusedAt(body *ast.BlockStmt, names map[string]token.Pos) token.Pos {
	for _, statement := range body.List {
		switch branch := statement.(type) {
		case *ast.IfStmt:
			// It has to turn somebody away. A question whose answer
			// *widens* what follows — "may they also read what nobody has
			// disclosed?" — is the same shape and the opposite act, and
			// taking it for a refusal exempts the function that asks it.
			if leaves(branch.Body) && refuses(branch.Cond, names) {
				return branch.Pos()
			}
		case *ast.SwitchStmt:
			// A switch with no tag is a chain of ifs, and a case refusing
			// is a refusal for whoever reaches it.
			if branch.Tag != nil {
				continue
			}
			for _, clause := range branch.Body.List {
				arm, ok := clause.(*ast.CaseClause)
				if !ok || !leaves(&ast.BlockStmt{List: arm.Body}) {
					continue
				}
				for _, cond := range arm.List {
					if refuses(cond, names) {
						return branch.Pos()
					}
				}
			}
		}
	}
	return token.NoPos
}

// refuses reports whether a condition is the refusal itself: the negation of a
// question asked of the subject about one of these names. A positive question
// that returns early answers those it admits and lets everybody else past.
func refuses(cond ast.Expr, names map[string]token.Pos) bool {
	negated, ok := cond.(*ast.UnaryExpr)
	if !ok || negated.Op != token.NOT {
		return false
	}
	asked, ok := negated.X.(*ast.CallExpr)
	if !ok || !carriesSubject(asked) {
		return false
	}
	namesBuild := false
	ast.Inspect(asked, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok {
			if base, ok := selector.X.(*ast.Ident); ok {
				if _, held := names[base.Name]; held {
					namesBuild = true
				}
			}
		}
		return true
	})
	return namesBuild
}

// leaves reports whether a branch ends the function, which is what makes it a
// refusal rather than a question whose answer changes what follows.
func leaves(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	switch body.List[len(body.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	}
	return false
}

// carriesSubject reports whether a call is asked of the subject or asks about
// it.
func carriesSubject(call *ast.CallExpr) bool {
	if fn, ok := call.Fun.(*ast.SelectorExpr); ok {
		if base, ok := fn.X.(*ast.Ident); ok && base.Name == subjectNamed {
			return true
		}
	}
	for _, argument := range call.Args {
		if named, ok := argument.(*ast.Ident); ok && named.Name == subjectNamed {
			return true
		}
	}
	return false
}
