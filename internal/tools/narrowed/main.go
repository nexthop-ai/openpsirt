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
// Nothing enforced that sentence. A collaborator on one embargoed issue
// received every approved statement for the whole build, because the read that
// followed the resolution checked whether one issue was undisclosed and never
// whether the subject could read the product at all. Two neighboring routes
// re-checked correctly. The difference between them was invisible: all three
// compiled, passed and answered.
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
// returned. So what a resolver hands back is followed as another name, and
// what a route collects into a list of builds with it. Anything further —
// a value carried through a struct field, or out of the function and back —
// is not followed, because a gate that did would be an analysis rather than a
// check. What it buys is that the next call site arrives announced rather than
// discovered.
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
	"locatedVisibly": true,
}

// subjectNamed is what the subject is called wherever it is carried. One name
// tree-wide, which is what lets this ask whether a call carries it.
const subjectNamed = "subject"

// resolving are calls that turn part of an address into another part of the
// same address. They answer nothing about findings, so they need no subject:
// what they return is the pair of names that was already resolved.
var resolving = map[string]string{
	"TargetFor":          "the build a release and a variant name",
	"ExistingTarget":     "the same, refusing one nothing has been filed against",
	"targetRow":          "the same, with the refusal a route answers",
	"Describe":           "how a build is spelled on screen",
	"ComponentAt":        "which component in that build a name stands for",
	"ComponentAs":        "the same, at a stated version",
	"ComponentAsIn":      "the same, refused where the name is held twice",
	"ComponentVersionAt": "the same, where the version is part of the address",
	"append":             "collecting resolved builds to ask about together",
}

// What a resolver hands back stands for the same permissive resolution and is
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
			// Only what this function holds directly. Anything inside a
			// closure is checked when the walk reaches that closure.
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
			resolved := resolvedIn(body)
			for name, at := range resolved {
				if inner(at) {
					delete(resolved, name)
				}
			}
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
	// What the address resolvers handed back, which is where nearly every
	// site does its reading.
	for name, from := range derivedIn(body, resolved) {
		if _, already := resolved[name]; !already {
			resolved[name] = from
			followed++
		}
	}
	loose := map[string][]token.Pos{}
	if held == 0 || refusedIn(body, resolved) {
		return loose, held, followed
	}
	for name := range resolved {
		if uses := unguarded(body, name); len(uses) > 0 {
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
func resolvedIn(body *ast.BlockStmt) map[string]token.Pos {
	found := map[string]token.Pos{}
	ast.Inspect(body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !permissive[called(call)] {
			return true
		}
		if name, ok := assign.Lhs[0].(*ast.Ident); ok && name.Name != "_" {
			found[name.Name] = assign.Pos()
		}
		return true
	})
	return found
}

// derivedIn returns what a call that resolves the rest of an address was bound
// to, given the names already resolved.
//
// The hop that consumed the check. Almost every site hands the resolved
// names straight to one of the address resolvers and then reads through what
// that returned, so the one use this program could see was the exempt one and
// there was nothing left to check. The build a resolver hands back stands for
// the same permissive resolution, so it is followed as another name.
func derivedIn(body *ast.BlockStmt, from map[string]token.Pos) map[string]token.Pos {
	found := map[string]token.Pos{}
	ast.Inspect(body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if _, address := resolving[called(call)]; !address {
			return true
		}
		if !mentions(call, from) {
			return true
		}
		if name, ok := assign.Lhs[0].(*ast.Ident); ok && name.Name != "_" {
			found[name.Name] = assign.Pos()
		}
		return true
	})
	return found
}

// mentions reports whether a call reads one of these names.
func mentions(call *ast.CallExpr, names map[string]token.Pos) bool {
	seen := false
	ast.Inspect(call, func(node ast.Node) bool {
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

		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		base, ok := selector.X.(*ast.Ident)
		if !ok || base.Name != name {
			return true
		}
		inACall := false
		for _, above := range path {
			call, ok := above.(*ast.CallExpr)
			if !ok {
				continue
			}
			inACall = true
			if carriesSubject(call) {
				return true
			}
			if _, address := resolving[called(call)]; address {
				return true
			}
		}
		// Returned rather than read: a resolver hands the names back, and its
		// own callers are checked here too.
		if inACall {
			loose = append(loose, selector.Pos())
		}
		return true
	})
	return loose
}

// refused reports whether the function opens by asking the subject about the
// build it just resolved, and turning them away.
//
// The test is deliberately narrow: the refusal stands in the function's own
// statement list, so that it covers everything after it. A check of the same
// shape nested inside another condition covers only what that condition
// covers, which is how a collaborator received a whole build's approved
// statements — the only subject question on that path was reached when the
// caller asked for undisclosed work, and a caller asking for what is published
// went past it.
func refusedIn(body *ast.BlockStmt, names map[string]token.Pos) bool {
	for _, statement := range body.List {
		branch, ok := statement.(*ast.IfStmt)
		if !ok {
			continue
		}
		// It has to turn somebody away. A question whose answer *widens* what
		// follows — "may they also read what nobody has disclosed?" — is the
		// same shape and the opposite act, and taking it for a refusal
		// exempts the function that asks it.
		if !leaves(branch) {
			continue
		}
		asksSubject, namesBuild := false, false
		ast.Inspect(branch.Cond, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && carriesSubject(call) {
				asksSubject = true
			}
			if selector, ok := node.(*ast.SelectorExpr); ok {
				if base, ok := selector.X.(*ast.Ident); ok {
					if _, held := names[base.Name]; held {
						namesBuild = true
					}
				}
			}
			return true
		})
		if asksSubject && namesBuild {
			return true
		}
	}
	return false
}

// leaves reports whether a branch ends the function, which is what makes it a
// refusal rather than a question whose answer changes what follows.
func leaves(branch *ast.IfStmt) bool {
	if len(branch.Body.List) == 0 {
		return false
	}
	switch branch.Body.List[len(branch.Body.List)-1].(type) {
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
