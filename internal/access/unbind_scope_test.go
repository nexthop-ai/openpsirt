// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Unbinding one person leaves every other pin where it is.
//
// Unbinding opens an authorization to redemption by name again, so an unbind
// that reached a second account would hand that account to whoever next
// arrives under its name. Verified by widening the unbind's person_id condition
// to one true of every row: bob's pin is cleared with hers.
func TestUnbindingOnePersonLeavesEveryoneElsePinned(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		alice := authorized(t, f, "alice", "alice")
		bob := authorized(t, f, "bob", "bob")
		if _, err := f.store.MatchProvider(ctx, "okta", "alice-1", "alice"); err != nil {
			t.Fatalf("alice's first sign-in was refused: %v", err)
		}
		if _, err := f.store.MatchProvider(ctx, "okta", "bob-1", "bob"); err != nil {
			t.Fatalf("bob's first sign-in was refused: %v", err)
		}

		if err := f.store.UnbindIdentifier(ctx, alice.ID); err != nil {
			t.Fatalf("unbinding was refused: %v", err)
		}

		identities, err := f.store.Identities(ctx, bob.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(identities) != 1 || identities[0].Subject == nil || *identities[0].Subject != "bob-1" {
			t.Fatalf("bob's pin moved when alice was unbound: %+v", identities)
		}
		if _, err := f.store.MatchProvider(ctx, "okta", "bob-2", "bob"); !errors.Is(err, access.ErrDenied) {
			t.Errorf("another identifier redeemed bob's account after alice was unbound: %v", err)
		}
	})
}
