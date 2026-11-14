// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// everyEstateRole is what a security team is typically granted across the
// estate: every reading role and the two triage roles over it.
var everyEstateRole = []access.Role{
	access.PublicRead, access.PrivateRead, access.SecurityTestingRead,
	access.PublicTriage, access.SecurityTestingTriage,
}

// A role across every product is access whatever the catalog holds. Spread over
// a catalog with nothing in it, it adds no per-product grant, so its holder is
// admitted on the role itself and reads nothing until a product exists.
func TestARoleAcrossEveryProductAdmitsSomebodyBeforeAnyProductExists(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		store := access.NewStore(db.DB)
		person, err := store.Ensure(ctx, "the-security-team", "The Security Team", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range everyEstateRole {
			if err := store.GrantEstateRole(ctx, person.ID, role); err != nil {
				t.Fatal(err)
			}
		}

		subject, err := store.Resolve(ctx, "the-security-team")
		if err != nil {
			t.Fatalf("somebody holding roles across every product was refused before any product exists: %v", err)
		}
		if products, all := subject.Products(); all || len(products) != 0 {
			t.Errorf("an empty catalog reads as products %v, all %v", products, all)
		}
		if known, all := subject.Knows(); all || len(known) != 0 {
			t.Errorf("an empty catalog is known as products %v, all %v", known, all)
		}
		if subject.Admin || subject.ReadsTheDeployment() {
			t.Error("admitting a role across every product made them an administrator or an auditor")
		}
		if !subject.HoldsAnywhere(access.PublicTriage) {
			t.Error("a triage role across every product is not held anywhere")
		}
		if subject.HoldsAnywhere(access.PrivateTriage, access.Approver) {
			t.Error("a role nobody granted is held anywhere")
		}

		// The first product declared is covered at the visibilities granted,
		// with nobody re-granted anything.
		product, err := catalog.NewStore(db.DB).DeclareProduct(ctx, "first", "First")
		if err != nil {
			t.Fatal(err)
		}
		subject, err = store.Resolve(ctx, "the-security-team")
		if err != nil {
			t.Fatal(err)
		}
		if !subject.Reads(access.Private, product.ID) || !subject.Triages(access.Public, product.ID) {
			t.Error("the first product declared is not covered by the roles across every product")
		}
	})
}

// Only a role in force admits. A row set aside, or one naming no role, grants
// nothing on a product and admits nobody to a catalog with none.
func TestARoleAcrossEveryProductNotInForceAdmitsNobody(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		store := access.NewStore(db.DB)
		for _, c := range []struct {
			identity string
			grant    access.EstateGrant
		}{
			{"set-aside", access.EstateGrant{Role: access.PublicRead, Source: access.Assigned, Active: false}},
			{"no-role", access.EstateGrant{Role: "not-a-role", Source: access.Assigned, Active: true}},
		} {
			person, err := store.Ensure(ctx, c.identity, c.identity, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			c.grant.PersonID = person.ID
			c.grant.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
			if _, err := db.DB.NewInsert().Model(&c.grant).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Resolve(ctx, c.identity); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s: a role across every product that grants nothing admitted them: %v", c.identity, err)
			}
		}
	})
}

// A token reads its owner's grants through the window a derived grant stays
// fresh for, and a role across every product a group derived before the window
// admits nothing through it, as a stale per-product grant reaches nothing.
func TestAStaleDerivedRoleAcrossEveryProductAdmitsNoToken(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		store := access.NewStore(db.DB)
		person, err := store.Ensure(ctx, "scripted", "Scripted", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		derived := access.EstateGrant{
			PersonID: person.ID, Role: access.PublicRead, Source: access.Derived, Active: true,
			CreatedAt: time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond),
		}
		if _, err := db.DB.NewInsert().Model(&derived).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		_, secret, err := store.NewToken(ctx, person.ID, "scripting", nil, nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		bounded := store.DerivingWithin(func(context.Context) time.Duration { return 24 * time.Hour })
		if _, err := bounded.ResolveToken(ctx, secret); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a role across every product derived before the window admitted a token: %v", err)
		}

		if _, err := db.DB.NewUpdate().Model((*access.EstateGrant)(nil)).
			Set(`"created_at" = ?`, time.Now().UTC().Truncate(time.Microsecond)).
			Where(`"id" = ?`, derived.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := bounded.ResolveToken(ctx, secret); err != nil {
			t.Errorf("a role across every product derived inside the window refused a token: %v", err)
		}
	})
}

// A token narrowed to some roles carries only those of the roles held across
// every product, as it carries only those of the roles held on a product.
func TestATokenNarrowedByRoleCarriesOnlyThoseRolesAcrossEveryProduct(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		store := access.NewStore(db.DB)
		person, err := store.Ensure(ctx, "scripted", "Scripted", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range []access.Role{access.PublicRead, access.PublicTriage} {
			if err := store.GrantEstateRole(ctx, person.ID, role); err != nil {
				t.Fatal(err)
			}
		}
		_, secret, err := store.NewToken(ctx, person.ID, "reading", nil,
			[]access.Role{access.PublicRead}, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		subject, err := store.ResolveToken(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		if !subject.HoldsAnywhere(access.PublicRead) {
			t.Error("a token lost the role it was minted for")
		}
		if subject.HoldsAnywhere(access.PublicTriage) {
			t.Error("a token minted for reading carries triage across every product")
		}
	})
}

func TestATokenPinnedToAProductHoldsNothingAcrossEveryProduct(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		store := access.NewStore(db.DB)
		product, err := catalog.NewStore(db.DB).DeclareProduct(ctx, "pinned", "pinned")
		if err != nil {
			t.Fatal(err)
		}
		person, err := store.Ensure(ctx, "scripted", "Scripted", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.GrantEstateRole(ctx, person.ID, access.PublicRead); err != nil {
			t.Fatal(err)
		}
		_, secret, err := store.NewToken(ctx, person.ID, "one product", &product.ID, nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		subject, err := store.ResolveToken(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		if !subject.HoldsAnywhere(access.PublicRead) {
			t.Error("a token pinned to a product lost the role it holds there")
		}
		if subject.HoldsEverywhere() {
			t.Error("a token pinned to one product says it covers every product as each is declared")
		}
	})
}
