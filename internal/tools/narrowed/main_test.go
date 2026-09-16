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

// bodyOf parses one function and hands back its body.
func bodyOf(t *testing.T, source string) *ast.BlockStmt {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\n"+source, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := file.Decls[0].(*ast.FuncDecl)
	if !ok {
		t.Fatal("the source is not a function")
	}
	return fn.Body
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
			// The ordinary handler shape: the read is narrowed in the data
			// layer, which is what carrying the subject into it means.
			"handed to something that carries the subject",
			`func f() {
				named, err := locatedVisibly(ctx, in, subject, product, stream, variant)
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
				named, err := locatedVisibly(ctx, in, subject, product, stream, variant)
				_ = err
				target, err := targetRow(ctx, in, named.StreamID, named.VariantID)
				_ = err
				planned, err := store.PendingUpgrades(ctx, target.ID)
				_ = planned
			}`,
			true,
		},
		{
			"the same, with the subject carried into the read",
			`func f() {
				named, err := locatedVisibly(ctx, in, subject, product, stream, variant)
				_ = err
				target, err := targetRow(ctx, in, named.StreamID, named.VariantID)
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
	} {
		body := bodyOf(t, c.source)
		resolved := resolvedIn(body)
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
