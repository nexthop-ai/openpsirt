package access_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// The hazard a provider change leaves behind.
//
// An identifier belongs to the provider that issued it. Once a deployment
// configures a different one, every account pinned to the old identifier is
// refused forever: the name matches, the identifier does not, and no sign-in
// path clears it — so without an administrative way to unbind, the only route
// back in is editing the database by hand.
func TestChangingProviderLocksEverybodyOutUntilTheIdentifierIsUnbound(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		alice := authorized(t, f, "alice", "alice")

		// The old provider, which pins its own identifier at her first
		// successful sign-in.
		if _, err := f.store.MatchProvider(ctx, "okta", "github-1001", "alice"); err != nil {
			t.Fatalf("the first sign-in was refused: %v", err)
		}

		// The deployment changes provider. The new one issues identifiers of
		// its own, so hers does not match what was pinned — which is the same
		// answer somebody who took a released name gets, and correctly so:
		// nothing here can tell the two apart.
		if _, err := f.store.MatchProvider(ctx, "okta", "okta-abc", "alice"); err == nil {
			t.Fatal("an identifier from a different provider was accepted, so a released name would be too")
		}

		// An administrator unbinds. The authorization stays: she was granted
		// access and that is not what went wrong.
		if err := f.store.UnbindIdentifier(ctx, alice.ID); err != nil {
			t.Fatalf("unbinding was refused: %v", err)
		}

		matched, err := f.store.MatchProvider(ctx, "okta", "okta-abc", "alice")
		if err != nil {
			t.Fatalf("she was still refused after unbinding: %v", err)
		}
		if matched.ID != alice.ID {
			t.Error("unbinding reached somebody else")
		}

		// And the new identifier is pinned, so the protection is back in force
		// from that sign-in rather than left open.
		identities, err := f.store.Identities(ctx, alice.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(identities) != 1 {
			t.Fatalf("one person has %d identities", len(identities))
		}
		if identities[0].Subject == nil || *identities[0].Subject != "okta-abc" {
			t.Fatalf("the new identifier was not pinned: %+v", identities[0])
		}
		if _, err := f.store.MatchProvider(ctx, "okta", "github-1001", "alice"); err == nil {
			t.Error("the old identifier still signs in, so unbinding widened rather than moved the pin")
		}
	})
}

// What it does not do: grant anybody anything. Unbinding is about how somebody
// arrives, and a person nobody authorized is refused after it exactly as
// before.
func TestUnbindingAnIdentifierGrantsNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		alice := authorized(t, f, "alice", "alice")
		if err := f.store.UnbindIdentifier(ctx, alice.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.MatchProvider(ctx, "okta", "okta-abc", "mallory"); err == nil {
			t.Error("somebody nobody authorized was let in")
		}
		// And an arrival with no identifier at all is still refused, which is
		// the rule unbinding must not quietly relax: an unpinned row is
		// redeemable by name, not by nothing.
		if _, err := f.store.MatchProvider(ctx, "okta", "", "alice"); err == nil {
			t.Error("an arrival naming no identifier redeemed an unbound authorization")
		}
	})
}

// Roles are untouched. Unbinding answers "how do they arrive", and answering it
// by taking their access away would make the recovery path a demotion.
func TestUnbindingAnIdentifierKeepsWhatTheyHold(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		alice := authorized(t, f, "alice", "alice")
		if err := f.store.UnbindIdentifier(ctx, alice.ID); err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.Resolve(ctx, "alice")
		if err != nil {
			t.Fatalf("she holds nothing after unbinding: %v", err)
		}
		if !subject.Reads(access.Public, f.products["sonic"]) {
			t.Error("unbinding took her role with it")
		}
	})
}
