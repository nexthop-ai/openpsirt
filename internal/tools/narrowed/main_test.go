// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The shape this exists for, and the shapes that are correct, read directly
// rather than through the program's exit code: a gate reached only by running
// it over the tree has one bit of evidence for whatever it found.

// bodyOf parses one function and hands back its body and the closures in it.
func bodyOf(t *testing.T, source string) (*ast.BlockStmt, []*ast.FuncLit) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\n"+source, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := file.Decls[0].(*ast.FuncDecl)
	if !ok {
		t.Fatal("the source is not a function")
	}
	var closures []*ast.FuncLit
	ast.Inspect(fn, func(node ast.Node) bool {
		if lit, ok := node.(*ast.FuncLit); ok {
			closures = append(closures, lit)
		}
		return true
	})
	return fn.Body, closures
}

func TestABuildResolvedForACollaborator(t *testing.T) {
	for _, c := range []struct {
		what     string
		source   string
		reported bool
	}{
		{
			// The disclosure this is for. The only subject question on the
			// path is reached when the caller asks for undisclosed work, so
			// a caller asking for what is published goes past it and the
			// statement reads the whole build.
			"a question about the subject that one branch reaches",
			`func f() {
				named, err := names.LocateVisible(ctx, subject, product, stream, variant)
				_ = err
				if undisclosed {
					if !subject.Reads(access.Private, named.ProductID) {
						return
					}
				}
				rows := db.NewSelect().Where("product_id = ?", named.ProductID).Scan(ctx)
				_ = rows
			}`,
			true,
		},
		{
			// The same shape flattened, and the opposite act: its answer
			// widens what follows rather than turning anybody away, so it
			// cannot stand for the product question the rest of the function
			// never asks.
			"a question whose answer widens what follows",
			`func f() {
				named, err := names.LocateVisible(ctx, subject, product, stream, variant)
				_ = err
				if subject.Reads(access.Private, named.ProductID) {
					visible = append(visible, access.Private)
				}
				rows := db.NewSelect().Where("product_id = ?", named.ProductID).Scan(ctx)
				_ = rows
			}`,
			true,
		},
		{
			"the same, refused for everybody before anything is read",
			`func f() {
				named, err := names.LocateVisible(ctx, subject, product, stream, variant)
				_ = err
				if !subject.Reads(access.Public, named.ProductID) {
					return nil, access.Denied("read findings here")
				}
				rows := db.NewSelect().Where("product_id = ?", named.ProductID).Scan(ctx)
				_ = rows
			}`,
			false,
		},
		{
			// A refusal covers what comes after it. A read before it has
			// already answered whoever asked.
			"read before the refusal",
			`func f() {
				named, err := names.LocateVisible(ctx, subject, product, stream, variant)
				_ = err
				rows := store.Unnarrowed(ctx, named.ProductID)
				if !subject.Reads(access.Public, named.ProductID) {
					return nil, access.Denied("read findings here")
				}
				_ = rows
			}`,
			true,
		},
		{
			// The ordinary handler shape: the read is narrowed in the data
			// layer, which is what carrying the subject into it means.
			"handed to something that carries the subject",
			`func f() {
				named, err := core.LocatedVisibly(ctx, in, subject, product, stream, variant)
				_ = err
				ready, err := store.ReadyFor(ctx, subject, named.ProductID, named.StreamID)
				_ = ready
			}`,
			false,
		},
		{
			// The hop nearly every site takes. The resolved names are used
			// once, by the resolver, and the read is keyed on what that
			// returned — so a check that stopped at the first use was
			// checking the exempt call and nothing else.
			"read through the build a resolver handed back",
			`func f() {
				named, err := core.LocatedVisibly(ctx, in, subject, product, stream, variant)
				_ = err
				target, err := core.TargetRow(ctx, in, named.StreamID, named.VariantID)
				_ = err
				planned, err := store.PendingUpgrades(ctx, target.ID)
				_ = planned
			}`,
			true,
		},
		{
			"the same, with the subject carried into the read",
			`func f() {
				named, err := core.LocatedVisibly(ctx, in, subject, product, stream, variant)
				_ = err
				target, err := core.TargetRow(ctx, in, named.StreamID, named.VariantID)
				_ = err
				planned, err := store.PendingUpgrades(ctx, subject, target.ID)
				_ = planned
			}`,
			false,
		},
		{
			// A route naming several builds resolves one per turn of a loop,
			// and a check reading only a function's own statement list sees
			// none of them.
			"resolved inside a loop over the builds a request names",
			`func f() {
				for _, build := range input.Body.Builds {
					at, err := names.LocateVisible(ctx, subject, product, build.Stream, build.Variant)
					_ = err
					rows := db.NewSelect().Where("target_id = ?", at.StreamID).Scan(ctx)
					_ = rows
				}
			}`,
			true,
		},
		{
			"resolved and bound with var rather than assigned",
			`func f() {
				var named, err = names.LocateVisible(ctx, subject, product, stream, variant)
				_ = err
				rows := db.NewSelect().Where("product_id = ?", named.ProductID).Scan(ctx)
				_ = rows
			}`,
			true,
		},
		{
			"read through the build a resolver handed back, bound with var",
			`func f() {
				named, err := core.LocatedVisibly(ctx, in, subject, product, stream, variant)
				_ = err
				var target, _ = core.TargetRow(ctx, in, named.StreamID, named.VariantID)
				planned, err := store.PendingUpgrades(ctx, target.ID)
				_ = planned
			}`,
			true,
		},
		{
			"resolved and handed back, which is what a resolver does",
			`func f() *catalog.Named {
				named, err := catalog.NewStore(db).LocateVisible(ctx, subject, product, stream, variant)
				if err != nil {
					return nil
				}
				return named
			}`,
			false,
		},
		{
			// A value copied from the resolution and handed on whole: not
			// a field of the resolved name, and one hop further than the
			// resolver's own answer.
			"copied into a list and handed on by name",
			`func f() {
				at, err := names.LocateVisible(ctx, subject, p, s, v)
				_ = err
				ids = append(ids, at.ProductID)
				store.Unnarrowed(ctx, ids)
			}`,
			true,
		},
		{
			"copied twice and read",
			`func f() {
				named, err := core.LocatedVisibly(ctx, in, subject, p, s, v)
				_ = err
				product := named.ProductID
				again := product
				store.Unnarrowed(ctx, again)
			}`,
			true,
		},
		{
			// A positive question that returns early answers those it
			// admits and lets everybody else past.
			"a positive question about the subject that returns early",
			`func f() {
				named, err := core.LocatedVisibly(ctx, in, subject, p, s, v)
				_ = err
				if subject.Reads(access.Private, named.ProductID) {
					return store.All(ctx, subject, named.ProductID)
				}
				return store.Published(ctx, named.ProductID)
			}`,
			true,
		},
		{
			// The subject reaches the outer call; the build reaches the inner
			// one first.
			"nested inside a call that carries the subject",
			`func f() {
				named, err := core.LocatedVisibly(ctx, in, subject, p, s, v)
				_ = err
				store.Narrow(ctx, subject, catalog.Unnarrowed(ctx, named.ProductID))
			}`,
			true,
		},
		{
			"a refusal in a switch with no tag",
			`func f() {
				named, err := core.LocatedVisibly(ctx, in, subject, p, s, v)
				_ = err
				switch {
				case subject.Kind == access.Pipeline:
					return
				case !subject.TriagesIn(named.ProductID):
					return
				}
				store.Unnarrowed(ctx, named.ProductID)
			}`,
			false,
		},
		{
			// The loop collecting builds a request names into a value that
			// carries the subject, the shape recording a flaw takes.
			"collected into a list handed to a read with the subject",
			`func f() {
				var targets []int64
				for _, build := range input.Body.Builds {
					at, err := names.LocateVisible(ctx, subject, p, build.Stream, build.Variant)
					_ = err
					target, err := core.TargetRow(ctx, in, at.StreamID, at.VariantID)
					_ = err
					targets = append(targets, target.ID)
				}
				store.Enter(ctx, subject, finding.Entering{TargetIDs: targets})
			}`,
			false,
		},
	} {
		body, closures := bodyOf(t, c.source)
		resolved := resolvedOutside(body, closures)
		if len(resolved) != 1 {
			t.Fatalf("%s: %d resolutions found, want the one in the source", c.what, len(resolved))
		}
		loose, held, _ := looseIn(body, resolved)
		if held != 1 {
			t.Errorf("%s: %d resolutions held", c.what, held)
		}
		if (len(loose) > 0) != c.reported {
			t.Errorf("%s: reported=%v, want %v", c.what, len(loose) > 0, c.reported)
		}
	}
}

func TestAClosureRebindingANameLeavesTheOuterResolution(t *testing.T) {
	// The outer resolution is read without a subject; a closure below binds
	// the same name again. Keyed by name with the last binding winning, the
	// closure's binding took the outer one away and the read went unreported.
	body, closures := bodyOf(t, `func f() {
		named, err := core.LocatedVisibly(ctx, in, subject, p, s, v)
		_ = err
		store.Unnarrowed(ctx, named.ProductID)
		h := func() {
			named, err := core.LocatedVisibly(ctx, in, subject, p, s, v)
			_, _ = named, err
		}
		_ = h
	}`)
	resolved := resolvedOutside(body, closures)
	if len(resolved) != 1 {
		t.Fatalf("%d outer resolutions found, want the one", len(resolved))
	}
	if loose, _, _ := looseIn(body, resolved); len(loose) == 0 {
		t.Error("the outer read without a subject was not reported")
	}
}
