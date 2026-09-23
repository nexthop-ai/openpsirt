// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package fixture seeds a world for a test to run against.
//
// It is a sibling of dbtest rather than part of it, because dbtest is imported
// by the database package's own tests and must not depend on the catalog or
// the access engine.
//
// No two attributes of the seeded world are accidentally equal. Every
// default differs from its neighbour on purpose, because the defect this
// package exists to expose is code that reads one attribute and answers with
// another. A seed written per package reaches for the value that collapses the
// axis it seeds — a display name that is the address name recapitalized, a
// person with no display name so every read of it falls back to their
// identity, one variant and it reaches customers, one stream and it is a
// branch — and under any of those, code answering a display name where an
// address name is resolved is indistinguishable from correct code.
//
// So the defaults here are:
//
//   - a product whose display name is not its name in other capitals
//   - a person whose display name is neither empty nor their identity
//   - two variants, one reaching customers and one not, carrying different
//     root component names
//   - two streams, a branch and a tag cut from it
//
// A test asserting a count over the seeded world counts against the fixture
// rather than against a literal, because the world has two of most things.
package fixture

import (
	"context"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// World is the seeded catalog and the stores that made it.
type World struct {
	DB      *database.DB
	Catalog *catalog.Store
	Access  *access.Store

	// Product is the one product every test has. Its display name is not its
	// name recapitalized, so a reader answering the display name where the
	// address name is resolved fails immediately rather than passing.
	Product *catalog.Product
	// Branch and Tag are the two streams. The tag's parent is the branch,
	// which is how a release compares against the line it was cut from.
	Branch *catalog.Stream
	Tag    *catalog.Stream
	// Customer reaches customers and Internal does not. Before this there was
	// no non-customer-facing variant anywhere in the repository, so every
	// narrowing, label and disclosure rule keyed on that flag was demonstrated
	// on one side only.
	Customer *catalog.Variant
	Internal *catalog.Variant
	// Target is the branch built as the customer-facing variant: the ordinary
	// place a finding sits.
	Target *catalog.Target
	// Person is somebody with a display name that is neither empty nor equal
	// to their identity, so a read of one can never coincide with the other.
	Person *access.Account

	t *testing.T
}

// Default names. Stated once, because a test that wants to look one of these
// up by name should name the same string the fixture seeded.
const (
	ProductName        = "sonic"
	ProductDisplayName = "Hardware Platform Images"
	BranchName         = "master"
	TagName            = "v2.4.1"
	CustomerVariant    = "broadcom"
	InternalVariant    = "lab-only"
	PersonIdentity     = "them@example.com"
	PersonDisplayName  = "Thea Example"
)

// Each runs fn against the seeded world on every engine, as dbtest.Each does.
func Each(t *testing.T, fn func(t *testing.T, w *World)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		fn(t, New(t, db))
	})
}

// Two runs fn against the seeded world on SQLite and PostgreSQL, as
// dbtest.Two does.
func Two(t *testing.T, fn func(t *testing.T, w *World)) {
	t.Helper()
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		fn(t, New(t, db))
	})
}

// New empties db and seeds the default world in it.
//
// The database arrives migrated, so nothing here migrates it. Reset is called
// because a package's tests share one database on the three server engines.
func New(t *testing.T, db *database.DB) *World {
	t.Helper()
	dbtest.Reset(t, db)
	w := &World{
		DB:      db,
		Catalog: catalog.NewStore(db.DB),
		Access:  access.NewStore(db.DB),
		t:       t,
	}
	w.Product = w.DeclareProduct(ProductName, ProductDisplayName)
	w.Branch = w.DeclareStream(w.Product, BranchName, catalog.Branch, nil)
	w.Tag = w.DeclareStream(w.Product, TagName, catalog.Tag, &w.Branch.ID)
	w.Customer = w.DeclareVariant(w.Product, CustomerVariant, true)
	w.Internal = w.DeclareVariant(w.Product, InternalVariant, false)
	w.Target = w.TargetFor(w.Branch, w.Customer)
	w.Person = w.DeclarePerson(PersonIdentity, PersonDisplayName, false)
	return w
}

// DeclareProduct adds a product, failing the test rather than returning an
// error: a fixture that could not be built is not a test result.
func (w *World) DeclareProduct(name, displayName string) *catalog.Product {
	w.t.Helper()
	product, err := w.Catalog.DeclareProduct(context.Background(), name, displayName)
	if err != nil {
		w.t.Fatalf("declare the product %q: %v", name, err)
	}
	return product
}

// DeclareStream adds a branch or a tag to a product.
func (w *World) DeclareStream(p *catalog.Product, name string, kind catalog.Kind, parent *int64) *catalog.Stream {
	w.t.Helper()
	stream, err := w.Catalog.DeclareStream(context.Background(), p.ID, name, kind, parent)
	if err != nil {
		w.t.Fatalf("declare the %s %q: %v", kind, name, err)
	}
	return stream
}

// DeclareVariant adds a way a product is built.
func (w *World) DeclareVariant(p *catalog.Product, name string, customerFacing bool) *catalog.Variant {
	w.t.Helper()
	variant, err := w.Catalog.DeclareVariant(context.Background(), p.ID, name, customerFacing)
	if err != nil {
		w.t.Fatalf("declare the variant %q: %v", name, err)
	}
	return variant
}

// TargetFor is the row for a stream built as a variant.
func (w *World) TargetFor(s *catalog.Stream, v *catalog.Variant) *catalog.Target {
	w.t.Helper()
	target, err := w.Catalog.TargetFor(context.Background(), s.ID, v.ID)
	if err != nil {
		w.t.Fatalf("place %s as %s: %v", s.Name, v.Name, err)
	}
	return target
}

// DeclarePerson adds somebody who may sign in.
//
// The display name is required rather than defaulted, because an empty one is
// the value that makes a read of a display name indistinguishable from a read
// of an identity — which is the whole reason this package exists.
func (w *World) DeclarePerson(identity, displayName string, admin bool) *access.Account {
	w.t.Helper()
	if displayName == "" {
		w.t.Fatalf("%q was declared with no display name: a read of it then "+
			"falls back to the identity, so a field answering the wrong one "+
			"cannot be told from a field answering the right one", identity)
	}
	person, err := w.Access.Ensure(context.Background(), identity, displayName, access.Stated(admin), nil)
	if err != nil {
		w.t.Fatalf("declare %q: %v", identity, err)
	}
	return person
}
