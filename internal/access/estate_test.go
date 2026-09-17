package access_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// The hazard this shape is written around. A role held across every product is
// still a role of one visibility, and the flag the queries already carry for
// "every product" means *no narrowing at all* — visibility included. Reusing
// it would have been the obvious change and would have handed somebody granted
// only disclosed reading every undisclosed finding in the deployment (REQ-43).
func TestAnEstateRoleReadsNoMoreThanItsVisibility(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "the-security-team", "The Security Team", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantEstateRole(ctx, person.ID, access.PublicRead); err != nil {
			t.Fatal(err)
		}

		subject, err := f.store.Resolve(ctx, "the-security-team")
		if err != nil {
			t.Fatalf("somebody holding a role over every product was refused: %v", err)
		}
		for name, id := range f.products {
			if !subject.Reads(access.Public, id) {
				t.Errorf("disclosed findings in %q are not readable", name)
			}
			if subject.Reads(access.Private, id) {
				t.Errorf("a disclosed-only role reads undisclosed findings in %q", name)
			}
		}

		// And the narrowing the queries do is by product, not "everything".
		// The flag is the deployment's own, and nothing a person holds sets it.
		products, all := subject.Products()
		if all {
			t.Fatal("an estate grant narrowed to nothing at all, which drops the visibility test too")
		}
		if len(products) != len(f.products) {
			t.Errorf("narrowing covers %d products, not the %d declared", len(products), len(f.products))
		}
	})
}

// The whole point of the grant: a product declared afterwards is covered,
// without anybody being re-granted anything. Expanding into a row per product
// would record the products of the moment the grant was made, which is the
// defect this replaces.
func TestAnEstateRoleCoversAProductDeclaredLater(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "the-security-team", "The Security Team", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantEstateRole(ctx, person.ID, access.PrivateRead); err != nil {
			t.Fatal(err)
		}

		later, err := f.catalog.DeclareProduct(ctx, "declared-later", "Declared Later")
		if err != nil {
			t.Fatal(err)
		}

		subject, err := f.store.Resolve(ctx, "the-security-team")
		if err != nil {
			t.Fatal(err)
		}
		if !subject.Reads(access.Private, later.ID) {
			t.Error("a product declared after the grant is not covered")
		}
		if !subject.Sees(later.ID) {
			t.Error("a product declared after the grant is invisible")
		}
	})
}

// Withdrawn whole, leaving nothing behind. Expanding into per-product grants
// at withdrawal would freeze the catalog as it stood that day, which is the
// same defect arriving by the back door.
func TestWithdrawingAnEstateRoleLeavesNothingBehind(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "the-security-team", "The Security Team", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		// One product held in its own right, so what comes back is the
		// per-product grant rather than everything or nothing.
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantEstateRole(ctx, person.ID, access.PrivateRead); err != nil {
			t.Fatal(err)
		}
		if err := f.store.WithdrawEstateRole(ctx, person.ID, access.PrivateRead); err != nil {
			t.Fatal(err)
		}

		subject, err := f.store.Resolve(ctx, "the-security-team")
		if err != nil {
			t.Fatal(err)
		}
		if subject.Reads(access.Private, f.products["onie"]) {
			t.Error("a withdrawn estate role still reads a product")
		}
		if !subject.Reads(access.Public, f.products["sonic"]) {
			t.Error("withdrawing the estate role took the per-product grant with it")
		}
		left, err := f.store.EstateGrants(ctx, person.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) != 0 {
			t.Errorf("withdrawing left %d rows behind", len(left))
		}
	})
}

// An estate grant is an assignment, so a change of role-assignment mode sets
// it aside and restores it exactly as it does the rest. A row that grants
// nothing must never be counted as access while it sits there.
func TestAnEstateRoleIsSetAsideAndRestoredByAModeSwitch(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "the-security-team", "The Security Team", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantEstateRole(ctx, person.ID, access.PrivateRead); err != nil {
			t.Fatal(err)
		}

		if err := f.store.SwitchTo(ctx, access.GroupBound); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Resolve(ctx, "the-security-team"); err == nil {
			t.Error("an estate role set aside by a mode switch still granted access")
		}

		if err := f.store.SwitchTo(ctx, access.Direct); err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.Resolve(ctx, "the-security-team")
		if err != nil {
			t.Fatalf("switching back did not restore the estate role: %v", err)
		}
		if !subject.Reads(access.Private, f.products["sonic"]) {
			t.Error("the restored estate role reaches nothing")
		}
	})
}
