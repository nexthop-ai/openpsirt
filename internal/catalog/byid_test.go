// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// Branches and variants named by identifier in one read are the rows each
// identifier names, and an identifier naming nothing is absent.
func TestBranchesAndTagsAndVariantsReadByIdentifierAreTheRowsTheyName(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		names := catalog.NewStore(db.DB)
		product, err := names.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		master, err := names.DeclareBranchOrTag(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		release, err := names.DeclareBranchOrTag(ctx, product.ID, "202505", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		broadcom, err := names.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}

		branchesAndTags, err := names.BranchesAndTagsByID(ctx, []int64{master.ID, release.ID, -1})
		if err != nil {
			t.Fatal(err)
		}
		if len(branchesAndTags) != 2 || branchesAndTags[master.ID].Name != "master" || branchesAndTags[release.ID].Name != "202505" {
			t.Errorf("read the branches as %+v", branchesAndTags)
		}
		variants, err := names.VariantsByID(ctx, []int64{broadcom.ID, -1})
		if err != nil {
			t.Fatal(err)
		}
		if len(variants) != 1 || variants[broadcom.ID].Name != "broadcom" {
			t.Errorf("read the variants as %+v", variants)
		}
		none, err := names.BranchesAndTagsByID(ctx, nil)
		if err != nil || len(none) != 0 {
			t.Errorf("no identifiers read %+v, %v", none, err)
		}
	})
}

// byID is one read of the catalog by an identifier, reduced to its error.
type byID struct {
	name string
	read func(ctx context.Context, s *catalog.Store, id int64) error
}

// byIDReads is every read of the catalog by an identifier that tells a row
// that is not there from a read that could not be made. The release being
// filled in is the identifier for the first fill-in case and the parent for
// the second, which holds a tag that exists.
func byIDReads(tag func() int64, db bun.IDB) []byID {
	return []byID{
		{"ProductOf", func(ctx context.Context, s *catalog.Store, id int64) error {
			_, err := s.ProductOf(ctx, id)
			return err
		}},
		{"Describe", func(ctx context.Context, s *catalog.Store, id int64) error {
			_, err := s.Describe(ctx, id)
			return err
		}},
		{"ProductByID", func(ctx context.Context, s *catalog.Store, id int64) error {
			_, err := s.ProductByID(ctx, id)
			return err
		}},
		{"BuildMoves", func(ctx context.Context, s *catalog.Store, id int64) error {
			_, err := s.BuildMoves(ctx, id)
			return err
		}},
		{"EndOfLifeForBuild", func(ctx context.Context, s *catalog.Store, id int64) error {
			_, err := s.EndOfLifeForBuild(ctx, id)
			return err
		}},
		{"ExistingBuild", func(ctx context.Context, s *catalog.Store, id int64) error {
			_, err := s.ExistingBuild(ctx, id, id)
			return err
		}},
		{"FillInParent of a release nobody declared", func(ctx context.Context, s *catalog.Store, id int64) error {
			_, err := s.FillInParent(ctx, id, id+1)
			return err
		}},
		{"FillInParent from a release nobody declared", func(ctx context.Context, s *catalog.Store, id int64) error {
			_, err := s.FillInParent(ctx, tag(), id)
			return err
		}},
		{"BuiltAs", func(ctx context.Context, s *catalog.Store, id int64) error {
			_, err := s.BuiltAs(ctx, administrator, id)
			return err
		}},
		{"MinimumSeverityOf", func(ctx context.Context, s *catalog.Store, id int64) error {
			_, err := s.MinimumSeverityOf(ctx, id)
			return err
		}},
		{"ReadsBuild", func(ctx context.Context, s *catalog.Store, id int64) error {
			return catalog.ReadsBuild(ctx, db, administrator, id)
		}},
		{"ReadsBuildIn", func(ctx context.Context, s *catalog.Store, id int64) error {
			return catalog.ReadsBuildIn(ctx, db, administrator, id, id)
		}},
	}
}

// administrator sees every product, so a read refused is refused for want of
// the row.
var administrator = access.NewPerson(1, "admin", true, nil, 0)

// Every exported read of this package that tells a missing row from a fault
// is in byIDReads, so the two tests over it cover each: found from the source,
// as every function whose body calls missingOr directly or through an
// unexported function, and each entry naming one.
func TestEveryReadByIdentifierIsListed(t *testing.T) {
	set := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	reads := map[string]bool{}
	calls := map[string]map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(set, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if ident, ok := call.Fun.(*ast.Ident); ok {
						if calls[fn.Name.Name] == nil {
							calls[fn.Name.Name] = map[string]bool{}
						}
						calls[fn.Name.Name][ident.Name] = true
					}
				}
				return true
			})
		}
	}
	// A read is an exported function calling missingOr, itself or through an
	// unexported function that does.
	for name, called := range calls {
		if !ast.IsExported(name) {
			continue
		}
		for callee := range called {
			if callee == "missingOr" || !ast.IsExported(callee) && calls[callee]["missingOr"] {
				reads[name] = true
			}
		}
	}
	if len(reads) == 0 {
		t.Fatal("no read calls missingOr in the source, so this checked nothing")
	}
	listed := map[string]bool{}
	for _, read := range byIDReads(func() int64 { return 1 }, nil) {
		listed[strings.Fields(read.name)[0]] = true
	}
	for name := range reads {
		if !listed[name] {
			t.Errorf("%s tells a missing row from a fault and byIDReads does not list it", name)
		}
	}
	for name := range listed {
		if _, ok := reflect.TypeFor[*catalog.Store]().MethodByName(name); !ok && !reads[name] {
			t.Errorf("byIDReads lists %s, which is no method of the store and no read found in the source", name)
		}
	}
}

// An identifier no row holds answers ErrNotFound and names the identifier,
// which is what a caller turns into "not declared" rather than a fault.
func TestAnIdentifierNothingHoldsIsNotDeclared(t *testing.T) {
	const nobody = int64(1) << 40
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		s := catalog.NewStore(db.DB)
		product, err := s.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		tag, err := s.DeclareBranchOrTag(ctx, product.ID, "v1.0", catalog.Tag, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, read := range byIDReads(func() int64 { return tag.ID }, db.DB) {
			err := read.read(ctx, s, nobody)
			if !errors.Is(err, catalog.ErrNotFound) {
				t.Errorf("%s of an identifier nothing holds answered %v", read.name, err)
				continue
			}
			// ExistingBuild is asked by a pair, and says which build in
			// words rather than by either identifier.
			if read.name != "ExistingBuild" && !strings.Contains(err.Error(), strconv.FormatInt(nobody, 10)) {
				t.Errorf("%s answered %q, which does not name the identifier", read.name, err)
			}
		}
	})
}

// A read that cannot be made is a fault, never ErrNotFound: a database that
// cannot answer is not one that answered "no such row".
func TestAReadThatCannotBeMadeIsNotAMiss(t *testing.T) {
	closed := dbtest.Closed(t).DB
	s := catalog.NewStore(closed)
	for _, read := range byIDReads(func() int64 { return 1 }, closed) {
		err := read.read(t.Context(), s, 1)
		if err == nil || errors.Is(err, catalog.ErrNotFound) {
			t.Errorf("%s against a database that cannot answer said %v", read.name, err)
		}
	}
}
