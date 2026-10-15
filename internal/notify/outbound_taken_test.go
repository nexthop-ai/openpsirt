// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// A destination added under a name and kind one in use already has is the
// administrator's to rename, and is refused in words rather than as a fault.
func TestADestinationNamedLikeOneInUseIsRefusedAsTaken(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana",
			new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		want := notify.Destination{
			Name: "paging", Kind: string(notify.Everything), URL: "https://hooks.example.com/a",
			Secret: "a-shared-secret-long-enough",
		}
		if _, err := store.AddDestination(ctx, asks(t, db, who), want, nil); err != nil {
			t.Fatal(err)
		}
		_, err = store.AddDestination(ctx, asks(t, db, who), want, nil)
		if !errors.Is(err, notify.ErrDestinationTaken) {
			t.Errorf("a second destination under one name and kind answered %v", err)
		}
	})
}

// A destination added again under a retired name and kind is the retired row
// taken up again, so what went there before stays recorded against it.
func TestADestinationAddedAgainUnderARetiredNameKeepsItsRow(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana",
			new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		first := notify.Destination{
			Name: "paging", Kind: string(notify.Everything), URL: "https://hooks.example.com/a",
			Secret: "a-shared-secret-long-enough",
		}
		added, err := store.AddDestination(ctx, asks(t, db, who), first, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.RetireDestination(ctx, asks(t, db, who), first.Name, first.Kind); err != nil {
			t.Fatal(err)
		}
		second := first
		second.URL = "https://hooks.example.com/b"
		again, err := store.AddDestination(ctx, asks(t, db, who), second, nil)
		if err != nil {
			t.Fatalf("adding a destination again under a retired name answered %v", err)
		}
		if again.ID != added.ID || again.URL != second.URL || again.RetiredAt != nil {
			t.Errorf("taken up again as id %d at %q retired %v, want id %d at %q in use",
				again.ID, again.URL, again.RetiredAt, added.ID, second.URL)
		}
	})
}
