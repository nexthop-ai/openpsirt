package catalog_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// each runs fn against every available engine, with the schema applied and the
// catalog emptied first so a persistent server behaves like a fresh one.
func each(t *testing.T, fn func(t *testing.T, db *database.DB, s *catalog.Store)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		dbtest.Reset(t, db)

		fn(t, db, catalog.NewStore(db.DB))
	})
}

// declared is a product with one branch and one variant, which is the smallest
// catalog anything can be filed against.
//
// Beside each() because three tests wrote these nine lines out, and a fourth
// wrote out each()'s body as well — so a change to how a test database is
// prepared landed in one place and silently missed the only test covering
// EnsureStream.
func declared(t *testing.T, ctx context.Context, s *catalog.Store) (
	*catalog.Product, *catalog.Stream, *catalog.Variant) {

	t.Helper()
	product, err := s.DeclareProduct(ctx, "SONiC", "SONiC")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := s.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
	if err != nil {
		t.Fatal(err)
	}
	variant, err := s.DeclareVariant(ctx, product.ID, "broadcom", true)
	if err != nil {
		t.Fatal(err)
	}
	return product, stream, variant
}

func TestDeclareAndResolve(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		p, err := s.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatalf("declare product: %v", err)
		}
		br, err := s.DeclareStream(ctx, p.ID, "release-2.4", catalog.Branch, nil)
		if err != nil {
			t.Fatalf("declare branch: %v", err)
		}
		// A tag records the branch it was cut from, which is what lets a
		// branch be compared against its last release.
		tag, err := s.DeclareStream(ctx, p.ID, "v2.4.1", catalog.Tag, &br.ID)
		if err != nil {
			t.Fatalf("declare tag: %v", err)
		}
		if tag.ParentID == nil || *tag.ParentID != br.ID {
			t.Errorf("tag lost its parent branch: %+v", tag.ParentID)
		}
		v, err := s.DeclareVariant(ctx, p.ID, "broadcom", true)
		if err != nil {
			t.Fatalf("declare variant: %v", err)
		}

		// Resolving records that this release is built as this variant. The
		// pair is not declared: the product, the release and the variant all
		// were, so a scan saying they go together reports a fact rather than
		// naming something new.
		got, err := s.Resolve(ctx, "sonic", "release-2.4", "broadcom")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got.StreamID != br.ID || got.VariantID != v.ID {
			t.Errorf("resolved to %+v", got)
		}
		// Resolving again is the same target, not a second one.
		again, err := s.Resolve(ctx, "sonic", "release-2.4", "broadcom")
		if err != nil || again.ID != got.ID {
			t.Errorf("resolving twice gave %v and %v (%v)", got.ID, again.ID, err)
		}

		// The same variant in another release is a different target over the
		// same variant, which is what stops the name being typed twice.
		other, err := s.Resolve(ctx, "sonic", "v2.4.1", "broadcom")
		if err != nil {
			t.Fatalf("resolve the tag: %v", err)
		}
		if other.VariantID != v.ID {
			t.Error("a release built as the same variant got a second variant")
		}
		if other.ID == got.ID {
			t.Error("two releases share one target")
		}
	})
}

func TestResolveNamesTheMissingPart(t *testing.T) {
	// Whoever sees the failed upload needs to know what to declare, not that
	// something somewhere was wrong.
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		p, _ := s.DeclareProduct(ctx, "sonic", "SONiC")
		_, _ = s.DeclareStream(ctx, p.ID, "release-2.4", catalog.Branch, nil)
		if _, err := s.DeclareVariant(ctx, p.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}

		for _, tc := range []struct{ product, stream, variant, want string }{
			{"nope", "release-2.4", "broadcom", `product "nope"`},
			{"sonic", "relase-2.4", "broadcom", `stream "relase-2.4"`},
			{"sonic", "release-2.4", "brodcom", `variant "brodcom"`},
		} {
			_, err := s.Resolve(ctx, tc.product, tc.stream, tc.variant)
			if err == nil {
				t.Errorf("%v resolved, but should not have", tc)
				continue
			}
			if !errors.Is(err, catalog.ErrNotFound) {
				t.Errorf("error is not ErrNotFound: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
		}
	})
}

func TestNamesAreUniqueWithinTheirParent(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		p, err := s.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeclareProduct(ctx, "sonic", "again"); !errors.Is(err, catalog.ErrExists) {
			t.Errorf("duplicate product accepted: %v", err)
		}
		a, err := s.DeclareStream(ctx, p.ID, "release-2.4", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeclareStream(ctx, p.ID, "release-2.4", catalog.Branch, nil); !errors.Is(err, catalog.ErrExists) {
			t.Errorf("duplicate stream accepted: %v", err)
		}
		if _, err := s.DeclareVariant(ctx, p.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		// A variant is declared once for the product. Declaring it again is
		// the same variant, not a second one — which is the whole point: a
		// release cannot introduce a second spelling of something the product
		// already builds.
		if _, err := s.DeclareVariant(ctx, p.ID, "broadcom", false); !errors.Is(err, catalog.ErrExists) {
			t.Errorf("duplicate variant accepted: %v", err)
		}

		// Every release is built as it without anyone restating the name.
		b, err := s.DeclareStream(ctx, p.ID, "release-2.5", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		// An administrator, because what this test is about is the catalog
		// rather than who may read it.
		admin := access.NewPerson(1, "admin", true, nil, 0)
		built, err := s.Variants(ctx, admin, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(built) != 1 {
			t.Errorf("the product builds %d variants, want 1", len(built))
		}
		// And a release only appears to be built as something once a scan has
		// been filed for it, which is what keeps a variant introduced later
		// out of earlier releases.
		for _, stream := range []int64{a.ID, b.ID} {
			was, err := s.BuiltAs(ctx, admin, stream)
			if err != nil {
				t.Fatal(err)
			}
			if len(was) != 0 {
				t.Errorf("a release nothing was filed against reports %d variants", len(was))
			}
		}
		if _, err := s.Resolve(ctx, "sonic", "release-2.5", "broadcom"); err != nil {
			t.Fatal(err)
		}
		was, err := s.BuiltAs(ctx, admin, b.ID)
		if err != nil || len(was) != 1 {
			t.Errorf("after a scan was filed the release reports %d variants (%v)", len(was), err)
		}
	})
}

func TestBadNamesAreRejected(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		for _, name := range []string{
			"", "   ", " leading", "trailing ", string(make([]byte, 200)),
			// One character over the column's width, and nothing else wrong
			// with it. The 200-byte name above is nul bytes, which the
			// control-character rule refuses first, so it says nothing about
			// the length bound.
			strings.Repeat("a", 192),
			// A name travels into places that are not this database: a path,
			// a header, the filename on an export somebody downloads. A
			// carriage return ends a header and a quote ends a quoted field
			// early, and neither is anything somebody meant to type.
			"ends\r\nX-Injected: yes", "quoted\"name", "with\ttab", "nul\x00byte",
		} {
			if _, err := s.DeclareProduct(ctx, name, ""); err == nil {
				t.Errorf("product name %q was accepted", name)
			}
		}

		// And the name one character shorter is declared. The pair pins both
		// edges, so the bound moving away from the column's width fails here
		// rather than as a truncated write on whichever engine is strict.
		if _, err := s.DeclareProduct(ctx, strings.Repeat("a", 191), ""); err != nil {
			t.Errorf("a name of exactly the column's width was refused: %v", err)
		}
	})
}

func TestStreamKindIsChecked(t *testing.T) {
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		p, _ := s.DeclareProduct(ctx, "sonic", "SONiC")
		if _, err := s.DeclareStream(ctx, p.ID, "x", catalog.Kind("release"), nil); err == nil {
			t.Error("an unrecognized stream kind was accepted")
		}
	})
}

func TestADeclaredNameIsFoundHoweverItIsCapitalized(t *testing.T) {
	// These names get typed by hand into build scripts. "sonic" reaching a
	// product declared as "SONiC" is the same typo problem that declaring
	// before use exists to catch — and refusing it teaches somebody the
	// product is not declared when it plainly is.
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, err := s.DeclareProduct(ctx, "SONiC", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeclareStream(ctx, product.ID, "Master", catalog.Branch, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeclareVariant(ctx, product.ID, "Broadcom", true); err != nil {
			t.Fatal(err)
		}

		for _, spelling := range []string{"sonic", "SONIC", "  SoNiC  "} {
			found, err := s.ProductByName(ctx, spelling)
			if err != nil {
				t.Errorf("looking up %q after declaring \"SONiC\": %v", spelling, err)
				continue
			}
			// And what comes back is what somebody wrote, not what we store
			// to compare with. Reading it back as "sonic" looks like the tool
			// got the name wrong.
			if found.DisplayName != "SONiC" {
				t.Errorf("the product reads back as %q", found.DisplayName)
			}
		}
		if _, err := s.StreamByName(ctx, product.ID, "master"); err != nil {
			t.Errorf("looking up stream \"master\" after declaring \"Master\": %v", err)
		}
		if _, err := s.VariantByName(ctx, product.ID, "BROADCOM"); err != nil {
			t.Errorf("looking up variant \"BROADCOM\" after declaring \"Broadcom\": %v", err)
		}

		// The other half: a second spelling is the same thing, so declaring it
		// again is declaring something that exists.
		if _, err := s.DeclareProduct(ctx, "sonic", "sonic"); !errors.Is(err, catalog.ErrExists) {
			t.Errorf("declaring \"sonic\" beside \"SONiC\" gave %v, want it to already exist", err)
		}
		if _, err := s.DeclareVariant(ctx, product.ID, "broadcom", true); !errors.Is(err, catalog.ErrExists) {
			t.Errorf("declaring \"broadcom\" beside \"Broadcom\" gave %v, want it to already exist", err)
		}
	})
}

func TestWhatAScanIsFiledAgainstIgnoresCapitals(t *testing.T) {
	// The case that matters in practice: a pipeline whose script spells the
	// variant differently from whoever declared it. Before this, that filed
	// against nothing and the upload was refused as undeclared.
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		declared(t, ctx, s)

		target, err := s.Resolve(ctx, "sonic", "MASTER", "Broadcom")
		if err != nil {
			t.Fatalf("a scan spelled differently was refused: %v", err)
		}
		where, err := s.Describe(ctx, target.ID)
		if err != nil {
			t.Fatal(err)
		}
		// And it describes itself the way people wrote it.
		if where.Product != "SONiC" || where.Stream != "master" || where.Variant != "broadcom" {
			t.Errorf("reads back as %s / %s / %s", where.Product, where.Stream, where.Variant)
		}
	})
}

func TestATagCanBeToldWhatItWasCutFromAfterwards(t *testing.T) {
	// Release readiness asks what was cut from this branch, so a tag declared
	// without saying leaves the branch reporting that nothing has ever been
	// released from it. There was no way to supply it later: re-declaring with
	// the parent was refused as a contradiction, which it is not — nothing had
	// been said for it to contradict.
	//
	// A claim that it came from a *different* branch stays refused, because a
	// tag is one frozen point and it came from wherever it came from.
	each(t, func(t *testing.T, _ *database.DB, store *catalog.Store) {
		ctx := t.Context()
		product, err := store.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		branch, err := store.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		other, err := store.DeclareStream(ctx, product.ID, "next", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}

		// Declared without saying where it came from, which is what a pipeline
		// that does not know will do.
		tag, created, err := store.EnsureStream(ctx, product.ID, "v1.0", catalog.Tag, nil)
		if err != nil || !created {
			t.Fatalf("declaring the tag: created=%v %v", created, err)
		}
		if tag.ParentID != nil {
			t.Fatal("a tag declared without a parent has one")
		}

		// Told afterwards, which fills the parent in rather than refusing.
		filled, created, err := store.EnsureStream(ctx, product.ID, "v1.0", catalog.Tag, &branch.ID)
		if err != nil {
			t.Fatalf("filling in what it was cut from: %v", err)
		}
		if created {
			t.Error("filling one in declared a second tag")
		}
		if filled.ParentID == nil || *filled.ParentID != branch.ID {
			t.Errorf("it was cut from %v, want the branch %d", filled.ParentID, branch.ID)
		}

		// And it is recorded, not merely returned.
		read, err := store.StreamByName(ctx, product.ID, "v1.0")
		if err != nil {
			t.Fatal(err)
		}
		if read.ParentID == nil || *read.ParentID != branch.ID {
			t.Errorf("what was written is %v, want the branch %d", read.ParentID, branch.ID)
		}

		// Moving it to a different branch is still a contradiction.
		if _, _, err := store.EnsureStream(ctx, product.ID, "v1.0", catalog.Tag, &other.ID); err == nil {
			t.Error("a tag was moved to a branch it was not cut from")
		}
	})
}

func TestRedeclaringSomethingDifferentlyIsRefusedAndChangesNothing(t *testing.T) {
	// The whole point of a declaration step: a pipeline that declares before
	// every build must not fail on the second one, and a pipeline that has
	// quietly changed what it means by a name must not pass.
	//
	// The tests above declare identically and assert the confirmation, which
	// exercises the agreeing half and none of the refusing one — and a
	// refusal nothing reaches is a rule that can be deleted with the suite
	// green. Each is checked twice over here: the call is refused, and the
	// stored value is read back to say the refusal wrote nothing.
	each(t, func(t *testing.T, _ *database.DB, s *catalog.Store) {
		ctx := t.Context()
		product, _, err := s.EnsureProduct(ctx, "sonic", "Hardware Platform Images")
		if err != nil {
			t.Fatal(err)
		}

		// A display name is what a person reads. Overwriting it on the next
		// pipeline run would let one build rename the product for everyone.
		if _, _, err := s.EnsureProduct(ctx, "sonic", "Something Else"); !errors.Is(err, catalog.ErrDiffers) {
			t.Errorf("redeclaring the product under another display name: %v", err)
		}
		again, err := s.ProductByName(ctx, "sonic")
		if err != nil {
			t.Fatal(err)
		}
		if again.DisplayName != "Hardware Platform Images" {
			t.Errorf("the refused call changed the display name to %q", again.DisplayName)
		}

		// A tag that became a branch would turn everything filed against it as
		// a frozen point into something rebuilt nightly.
		if _, _, err := s.EnsureStream(ctx, product.ID, "v1.0", catalog.Tag, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.EnsureStream(ctx, product.ID, "v1.0", catalog.Branch, nil); !errors.Is(err, catalog.ErrDiffers) {
			t.Errorf("redeclaring a tag as a branch: %v", err)
		}
		stream, err := s.StreamByName(ctx, product.ID, "v1.0")
		if err != nil {
			t.Fatal(err)
		}
		if stream.Kind != catalog.Tag {
			t.Errorf("the refused call made it a %s", stream.Kind)
		}

		// A thing's reach to customers feeds how its findings rank, so
		// a change here changes what people are told to work on first.
		if _, _, err := s.EnsureVariant(ctx, product.ID, "lab-only", false); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.EnsureVariant(ctx, product.ID, "lab-only", true); !errors.Is(err, catalog.ErrDiffers) {
			t.Errorf("redeclaring an internal variant as customer-facing: %v", err)
		}
		variant, err := s.VariantByName(ctx, product.ID, "lab-only")
		if err != nil {
			t.Fatal(err)
		}
		if variant.CustomerFacing {
			t.Error("the refused call made an internal variant customer-facing")
		}
		// And the refusal says which it was, because "already declared,
		// differently" without saying how is a message somebody has to go
		// and look the answer up for.
		_, _, err = s.EnsureVariant(ctx, product.ID, "lab-only", true)
		if !strings.Contains(err.Error(), "internal") {
			t.Errorf("the refusal does not say what it was declared as: %v", err)
		}
	})
}
