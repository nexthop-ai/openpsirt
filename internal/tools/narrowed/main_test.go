package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The shape this exists for, and the shape that is correct, read directly
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
			"the same, refused for everybody before anything is read",
			`func f() {
				named, err := names.LocateVisible(ctx, subject, product, stream, variant)
				_ = err
				if !subject.Reads(access.Public, named.ProductID) {
					return
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
			"used to resolve the rest of the address, which answers nothing about findings",
			`func f() {
				named, err := locatedVisibly(ctx, in, subject, product, stream, variant)
				_ = err
				target, err := names.TargetFor(ctx, named.StreamID, named.VariantID)
				_ = target
			}`,
			false,
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
		for name := range resolved {
			loose := refused(body, name) == false && len(unguarded(body, name)) > 0
			if loose != c.reported {
				t.Errorf("%s: reported=%v, want %v", c.what, loose, c.reported)
			}
		}
	}
}
