// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// TestARetiredVariantLeavesTheOfferedListAndNotTheBuiltList pins the split
// that makes retiring safe: what a product declares stops offering it, and
// what a release was actually built as keeps it.
//
// Dropped from both, a release holding findings against it would stop naming
// where they are, and read as a release that does not hold them.
func TestARetiredVariantLeavesTheOfferedListAndNotTheBuiltList(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, stream, variant := declared(t, ctx, s)
		if _, err := s.TargetFor(ctx, stream.ID, variant.ID); err != nil {
			t.Fatal(err)
		}
		admin := access.NewPerson(1, "admin", true, nil, 0)

		if err := s.RetireVariant(ctx, variant.ID); err != nil {
			t.Fatalf("retire: %v", err)
		}

		offered, err := s.Variants(ctx, admin, product.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(offered) != 0 {
			t.Errorf("a retired variant is still offered: %+v", offered)
		}

		built, err := s.BuiltAs(ctx, admin, stream.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(built) != 1 || built[0].ID != variant.ID {
			t.Fatalf("the release stopped naming what it was built as: %+v", built)
		}
		if !built[0].Retired() {
			t.Error("the release names it without saying it is retired")
		}
	})
}

// TestARetiredVariantStillResolvesByName pins that retiring hides a variant
// without stranding what was filed against it.
//
// Its findings are open, its decisions stand and the documents issued for it
// name it, and every one of those is reached by resolving the name.
func TestARetiredVariantStillResolvesByName(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, _, variant := declared(t, ctx, s)
		if err := s.RetireVariant(ctx, variant.ID); err != nil {
			t.Fatal(err)
		}

		found, err := s.VariantByName(ctx, product.ID, "broadcom")
		if err != nil {
			t.Fatalf("a retired variant no longer resolves: %v", err)
		}
		if !found.Retired() {
			t.Error("it resolved without saying it is retired")
		}

		named, err := s.Locate(ctx, "SONiC", "master", "broadcom")
		if err != nil {
			t.Fatalf("the build no longer locates: %v", err)
		}
		if !named.VariantRetired {
			t.Error("the located build does not say its variant is retired")
		}
	})
}

// TestRetiringTwiceIsRefused pins that the second one is told so.
//
// Answered as done, two administrators retiring it at once would both record
// having done it, and the record would say it happened twice.
func TestRetiringTwiceIsRefused(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		_, _, variant := declared(t, ctx, s)
		if err := s.RetireVariant(ctx, variant.ID); err != nil {
			t.Fatal(err)
		}
		if err := s.RetireVariant(ctx, variant.ID); !errors.Is(err, catalog.ErrNotFound) {
			t.Errorf("retiring a retired variant answered %v", err)
		}
	})
}

// TestDeclaringARetiredVariantBringsItBack pins what keeps declaring
// idempotent.
//
// A pipeline runs the declaration on every build and the name is still spoken
// for while retired, so the alternative is a build script that starts failing
// because an administrator tidied a list.
func TestDeclaringARetiredVariantBringsItBack(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, _, variant := declared(t, ctx, s)
		if err := s.RetireVariant(ctx, variant.ID); err != nil {
			t.Fatal(err)
		}

		back, made, err := s.EnsureVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatalf("declaring a retired variant: %v", err)
		}
		if back.ID != variant.ID {
			t.Errorf("a second variant was made: %d beside %d", back.ID, variant.ID)
		}
		if !made {
			t.Error("bringing one back is reported as having found it already in use")
		}
		if back.Retired() {
			t.Error("it came back still retired")
		}

		admin := access.NewPerson(1, "admin", true, nil, 0)
		offered, err := s.Variants(ctx, admin, product.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(offered) != 1 {
			t.Errorf("it is not offered again: %+v", offered)
		}
	})
}

// TestBringingBackAVariantKeepsWhatItReaches pins that the reach a retired
// variant was declared with still has to match.
//
// It feeds ranking, and a declaration that quietly redefined it on the way
// back would move what everybody is told to work on first.
func TestBringingBackAVariantKeepsWhatItReaches(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, _, variant := declared(t, ctx, s)
		if err := s.RetireVariant(ctx, variant.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.EnsureVariant(ctx, product.ID, "broadcom", false); !errors.Is(err, catalog.ErrDiffers) {
			t.Errorf("bringing it back as something else answered %v", err)
		}
	})
}

// TestRenamingOntoATakenNameIsRefused pins that a retired variant keeps
// holding its name.
//
// The unique constraint covers a retired row, so without this the caller gets
// a constraint violation instead of the reason.
func TestRenamingOntoATakenNameIsRefused(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, _, variant := declared(t, ctx, s)
		other, err := s.DeclareVariant(ctx, product.ID, "lab-only", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RetireVariant(ctx, other.ID); err != nil {
			t.Fatal(err)
		}

		if err := s.RenameVariant(ctx, product.ID, variant.ID, "lab-only"); !errors.Is(err, catalog.ErrExists) {
			t.Errorf("renaming onto a retired name answered %v", err)
		}
		if err := s.RenameVariant(ctx, product.ID, variant.ID, "LAB-ONLY"); !errors.Is(err, catalog.ErrExists) {
			t.Errorf("renaming onto a retired name in other capitals answered %v", err)
		}
	})
}

// TestRenamingMovesBothHalvesOfTheName pins that the matching name and the
// spelling shown back move together.
//
// A name people type is matched without regard to capitals, so the two are
// derived from one string and a rename that moved only one would leave a
// variant matched as one thing and shown as another.
func TestRenamingMovesBothHalvesOfTheName(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, _, variant := declared(t, ctx, s)
		if err := s.RenameVariant(ctx, product.ID, variant.ID, "Broadcom-DNX"); err != nil {
			t.Fatalf("rename: %v", err)
		}

		found, err := s.VariantByName(ctx, product.ID, "broadcom-dnx")
		if err != nil {
			t.Fatalf("the new name does not match: %v", err)
		}
		if found.Name != "broadcom-dnx" {
			t.Errorf("it is matched as %q", found.Name)
		}
		if found.DisplayName != "Broadcom-DNX" {
			t.Errorf("it is shown as %q", found.DisplayName)
		}
		if _, err := s.VariantByName(ctx, product.ID, "broadcom"); !errors.Is(err, catalog.ErrNotFound) {
			t.Errorf("the old name still matches: %v", err)
		}
	})
}

// TestCorrectingWhatAVariantReaches pins the act that was missing.
//
// A pipeline is refused this on its next run because it feeds ranking, and
// before this there was no deliberate path either: declared wrongly once, it
// could not be corrected at all.
func TestCorrectingWhatAVariantReaches(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, _, variant := declared(t, ctx, s)
		if err := s.SetVariantCustomerFacing(ctx, variant.ID, false); err != nil {
			t.Fatalf("correct what it reaches: %v", err)
		}
		found, err := s.VariantByName(ctx, product.ID, "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		if found.CustomerFacing {
			t.Error("it still reads as reaching customers")
		}
	})
}

// TestARetiredProductAndReleaseLeaveTheOfferedLists pins that the two levels
// above a variant follow the same rule: what a product declares stops offering
// what is out of use.
func TestARetiredProductAndReleaseLeaveTheOfferedLists(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, stream, _ := declared(t, ctx, s)
		admin := access.NewPerson(1, "admin", true, nil, 0)

		if err := s.RetireStream(ctx, stream.ID); err != nil {
			t.Fatalf("retire the release: %v", err)
		}
		lines, err := s.Streams(ctx, admin, product.ID, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) != 0 {
			t.Errorf("a retired release is still offered: %+v", lines)
		}

		if err := s.RetireProduct(ctx, product.ID); err != nil {
			t.Fatalf("retire the product: %v", err)
		}
		products, err := s.Products(ctx, admin)
		if err != nil {
			t.Fatal(err)
		}
		if len(products) != 0 {
			t.Errorf("a retired product is still offered: %+v", products)
		}
	})
}

// TestARetiredProductAndReleaseStillResolveByName pins that retiring the two
// levels above a variant strands nothing either.
func TestARetiredProductAndReleaseStillResolveByName(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, stream, _ := declared(t, ctx, s)
		if err := s.RetireStream(ctx, stream.ID); err != nil {
			t.Fatal(err)
		}
		if err := s.RetireProduct(ctx, product.ID); err != nil {
			t.Fatal(err)
		}

		named, err := s.Locate(ctx, "SONiC", "master", "broadcom")
		if err != nil {
			t.Fatalf("the build no longer locates: %v", err)
		}
		if !named.ProductRetired || !named.StreamRetired {
			t.Errorf("the located build does not say what is retired: %+v", named)
		}
		if named.VariantRetired {
			t.Error("retiring a product retired its variants too")
		}
	})
}

// TestRetiringAProductLeavesItsReleasesAlone pins that nothing is written onto
// what sits under a retired product.
//
// They go out of every list with it because they are reached through it, and
// bringing the product back has nothing to remember.
func TestRetiringAProductLeavesItsReleasesAlone(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, _, _ := declared(t, ctx, s)
		if err := s.RetireProduct(ctx, product.ID); err != nil {
			t.Fatal(err)
		}

		back, made, err := s.EnsureProduct(ctx, "SONiC", "SONiC")
		if err != nil {
			t.Fatalf("declaring a retired product: %v", err)
		}
		if back.ID != product.ID || !made || back.Retired() {
			t.Fatalf("it did not come back as itself: %+v made=%v", back, made)
		}

		admin := access.NewPerson(1, "admin", true, nil, 0)
		lines, err := s.Streams(ctx, admin, product.ID, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) != 1 {
			t.Errorf("its releases did not come back with it: %+v", lines)
		}
		built, err := s.Variants(ctx, admin, product.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(built) != 1 {
			t.Errorf("its variants did not come back with it: %+v", built)
		}
	})
}

// TestDeclaringARetiredReleaseBringsItBack pins the same idempotency a variant
// and a product keep.
func TestDeclaringARetiredReleaseBringsItBack(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, stream, _ := declared(t, ctx, s)
		if err := s.RetireStream(ctx, stream.ID); err != nil {
			t.Fatal(err)
		}
		back, made, err := s.EnsureStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatalf("declaring a retired release: %v", err)
		}
		if back.ID != stream.ID || !made || back.Retired() {
			t.Fatalf("it did not come back as itself: %+v made=%v", back, made)
		}
	})
}

// TestAProductsDisplayNameMovesWithoutItsName pins that the two are separate
// acts on a product.
//
// The name is what a published document is identified by; the display name is
// what a screen and a document's prose show, and nothing is identified by it.
func TestAProductsDisplayNameMovesWithoutItsName(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, _, _ := declared(t, ctx, s)
		if err := s.SetProductDisplayName(ctx, product.ID, "SONiC on Broadcom"); err != nil {
			t.Fatalf("correct what it is shown as: %v", err)
		}
		found, err := s.ProductByName(ctx, "sonic")
		if err != nil {
			t.Fatalf("the name moved with the display name: %v", err)
		}
		if found.DisplayName != "SONiC on Broadcom" {
			t.Errorf("it is shown as %q", found.DisplayName)
		}
	})
}

// TestRenamingAProductOntoATakenNameIsRefused pins that a retired product
// keeps holding its name, the way a retired variant does.
func TestRenamingAProductOntoATakenNameIsRefused(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, _, _ := declared(t, ctx, s)
		other, err := s.DeclareProduct(ctx, "onie", "ONIE")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RetireProduct(ctx, other.ID); err != nil {
			t.Fatal(err)
		}
		if err := s.RenameProduct(ctx, product.ID, "ONIE"); !errors.Is(err, catalog.ErrExists) {
			t.Errorf("renaming onto a retired product's name answered %v", err)
		}
	})
}
