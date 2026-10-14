// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// The floor is the store's, so every caller that records a webhook is held to
// it rather than only the route that took the request.
func TestAWebhookSecretShorterThanTheFloorIsRefusedByTheStore(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
		admin, err := access.NewStore(db.DB).Ensure(ctx, "admin@example.com", "Admin",
			access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		add := func(secret string) error {
			_, err := store.AddDestination(ctx, asks(t, db, admin), notify.Destination{
				Name: "hook-" + fmt.Sprint(len([]rune(secret))), Kind: notify.Everything,
				URL: "https://hooks.example.com/in", Secret: secret,
			}, nil)
			return err
		}
		// Counted in characters: sixteen of them is enough however many bytes
		// they take.
		if err := add(strings.Repeat("€", notify.ShortestSecret)); err != nil {
			t.Fatalf("a secret of exactly the floor was refused: %v", err)
		}
		err = add(strings.Repeat("€", notify.ShortestSecret-1))
		if !refusal.In(err) || !strings.Contains(err.Error(), "at least 16") {
			t.Errorf("a secret one character short answered %v", err)
		}
	})
}
