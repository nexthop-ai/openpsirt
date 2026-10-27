// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

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
func byIDReads(tag func() int64) []byID {
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
		for _, read := range byIDReads(func() int64 { return tag.ID }) {
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
	s := catalog.NewStore(dbtest.Closed(t).DB)
	for _, read := range byIDReads(func() int64 { return 1 }) {
		err := read.read(t.Context(), s, 1)
		if err == nil || errors.Is(err, catalog.ErrNotFound) {
			t.Errorf("%s against a database that cannot answer said %v", read.name, err)
		}
	}
}
