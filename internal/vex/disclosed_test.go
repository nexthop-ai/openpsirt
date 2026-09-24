// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

func TestEveryReadOfABuildsDocumentAsksForDisclosedReading(t *testing.T) {
	// A document is disclosed work alone, and a row saying one went out is as
	// much a disclosure as the document. Reading only undisclosed work in the
	// product reaches neither: not the document, not the record of what went
	// out, not whether it changed, and not the bytes that were sent.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		if _, err := cat.Resolve(ctx, "sonic", "master", "broadcom"); err != nil {
			t.Fatal(err)
		}
		person, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana",
			access.Stated(false), nil)
		if err != nil {
			t.Fatal(err)
		}
		as := func(roles ...access.Role) access.Subject {
			return access.NewPerson(person.ID, person.Email, false,
				map[int64][]access.Role{product.ID: roles}, 0)
		}
		named := publisher.Named{Name: "Example Networks", Namespace: "https://example.test"}
		store := vex.NewStore(db.DB)

		// One document out, so every read below has something to answer with
		// when it is not refused.
		if _, err := store.Issued(ctx, as(access.PublicTriage), named,
			"sonic", "master", "broadcom"); err != nil {
			t.Fatal(err)
		}

		reads := []struct {
			what string
			ask  func(access.Subject) error
		}{
			{"the document", func(s access.Subject) error {
				_, err := store.For(ctx, s, named, "sonic", "master", "broadcom", false)
				return err
			}},
			{"the document with undisclosed work", func(s access.Subject) error {
				_, err := store.For(ctx, s, named, "sonic", "master", "broadcom", true)
				return err
			}},
			{"what went out", func(s access.Subject) error {
				_, err := store.Issuances(ctx, s, "sonic", "master", "broadcom")
				return err
			}},
			{"whether it changed", func(s access.Subject) error {
				_, err := store.Changed(ctx, s, named, "sonic", "master", "broadcom")
				return err
			}},
			{"what was sent", func(s access.Subject) error {
				_, err := store.Sent(ctx, s, "sonic", "master", "broadcom", 1)
				return err
			}},
		}
		for _, who := range []struct {
			what  string
			roles []access.Role
		}{
			{"a private reader", []access.Role{access.PrivateRead}},
			{"a private triager", []access.Role{access.PrivateTriage}},
		} {
			for _, read := range reads {
				if err := read.ask(as(who.roles...)); !errors.Is(err, access.ErrDenied) {
					t.Errorf("%s asking for %s got %v, want a refusal", who.what, read.what, err)
				}
			}
		}

		// A reader of both halves is answered by every one of them, so the
		// refusals above are about the grant rather than about the build.
		both := as(access.PublicRead, access.PrivateRead)
		for _, read := range reads {
			if err := read.ask(both); err != nil {
				t.Errorf("a reader of both halves asking for %s was refused: %v", read.what, err)
			}
		}
	})
}
