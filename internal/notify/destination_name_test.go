// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// A destination's name is typed, so it is matched without regard to capitals
// and shown as it was typed: one spelling cannot add a second destination
// beside another, and any spelling retires it.
func TestADestinationNameIsMatchedWhateverItsCapitals(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		admin := asks(t, db, who)
		store := notify.NewStore(db.DB)
		add := func(name string) error {
			_, err := store.AddDestination(ctx, admin, notify.Destination{
				Name: name, Kind: notify.Everything, URL: "https://hooks.example/x",
				Secret: "a-shared-secret-long-enough",
			}, nil)
			return err
		}
		listed := func() []string {
			t.Helper()
			rows, err := store.Destinations(ctx, admin)
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(rows))
			for _, row := range rows {
				names = append(names, row.Name)
			}
			return names
		}

		if err := add(" Ops-Pager "); err != nil {
			t.Fatal(err)
		}
		if got := listed(); len(got) != 1 || got[0] != "Ops-Pager" {
			t.Errorf("listed as %q, want the spelling typed", got)
		}
		if err := add("ops-pager"); err == nil {
			t.Error("a second destination was added under the same name in other capitals")
		}
		if _, err := store.RetireDestination(ctx, admin, "OPS-PAGER", notify.Everything); err != nil {
			t.Fatalf("retiring in other capitals: %v", err)
		}
		if got := listed(); len(got) != 0 {
			t.Errorf("still listed after it was retired: %q", got)
		}
		if err := add("ops-Pager"); err != nil {
			t.Fatalf("taking it up again in other capitals: %v", err)
		}
		if got := listed(); len(got) != 1 || got[0] != "ops-Pager" {
			t.Errorf("taken up again and listed as %q, want the new spelling", got)
		}
	})
}
