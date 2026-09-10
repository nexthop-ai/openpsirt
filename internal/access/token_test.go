package access_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// holder is somebody with a role and a token of their own.
func holder(t *testing.T, f *fixture) (*access.Account, string) {
	t.Helper()
	ctx := t.Context()
	person, err := f.store.Ensure(ctx, "someone", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
		t.Fatal(err)
	}
	if err := f.store.GrantRole(ctx, person.ID, f.products["onie"], access.PublicRead); err != nil {
		t.Fatal(err)
	}
	_, secret, err := f.store.NewToken(ctx, person.ID, "scripting", nil, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	return person, secret
}

func TestATokenReachesWhatItsOwnerReaches(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		_, secret := holder(t, f)
		subject, err := f.store.ResolveToken(t.Context(), secret)
		if err != nil {
			t.Fatal(err)
		}
		if !subject.Reads(access.Public, f.products["sonic"]) ||
			!subject.Reads(access.Public, f.products["onie"]) {
			t.Errorf("a token reached less than its owner: %+v", subject)
		}
	})
}

func TestATokenShrinksWhenItsOwnerDoes(t *testing.T) {
	// A live reference rather than a snapshot. A snapshot would quietly
	// outlive the access it was granted from — including a role withdrawn by a
	// group membership going away, which is the case with nothing to notice.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, secret := holder(t, f)

		if err := f.store.Withdraw(ctx, person.ID, f.products["onie"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.ResolveToken(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		if subject.Reads(access.Public, f.products["onie"]) {
			t.Error("a token kept reaching a product its owner no longer holds")
		}
		if !subject.Reads(access.Public, f.products["sonic"]) {
			t.Error("a token lost what its owner still holds")
		}

		// And when the owner holds nothing at all, so does the token.
		if err := f.store.Withdraw(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ResolveToken(ctx, secret); err == nil {
			t.Error("a token outlived every role its owner had")
		}
	})
}

func TestANarrowedTokenReachesLessThanItsOwnerAndNeverMore(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, _ := holder(t, f)

		sonic := f.products["sonic"]
		_, narrowed, err := f.store.NewToken(ctx, person.ID, "sonic-only", &sonic, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.ResolveToken(ctx, narrowed)
		if err != nil {
			t.Fatal(err)
		}
		if !subject.Reads(access.Public, sonic) {
			t.Error("a narrowed token lost the product it was narrowed to")
		}
		if subject.Reads(access.Public, f.products["onie"]) {
			t.Error("a narrowed token reached beyond what it was narrowed to")
		}

		// Narrowing intersects: pinned to something its owner cannot read, it
		// reaches nothing rather than being granted it.
		if err := f.store.Withdraw(ctx, person.ID, sonic, access.PublicRead); err != nil {
			t.Fatal(err)
		}
		// Asserted unconditionally. Guarding this on the resolution succeeding
		// would make the property stop being checked the moment resolution
		// failed for any unrelated reason, and the test would still pass.
		switch subject, err := f.store.ResolveToken(ctx, narrowed); {
		case err == nil && subject.Reads(access.Public, sonic):
			t.Error("narrowing granted what its owner had lost")
		case err == nil:
			if reached, all := subject.Products(); all || len(reached) != 0 {
				t.Errorf("a token whose owner holds nothing still reaches %v (all=%v)", reached, all)
			}
		}
	})
}

func TestATokenNarrowedToAProductCarriesNoAdministration(t *testing.T) {
	// Administration is global. A token narrowed to one product that still
	// administered everything would not be narrowed at all.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "an-admin", "", true)
		if err != nil {
			t.Fatal(err)
		}
		sonic := f.products["sonic"]
		_, secret, err := f.store.NewToken(ctx, person.ID, "narrow", &sonic, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		subject, err := f.store.ResolveToken(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		if subject.Admin {
			t.Error("a token narrowed to one product still administered everything")
		}
	})
}

func TestATokenHasToExpireAndCannotOutlastTheCeiling(t *testing.T) {
	// A credential that never runs out is one nobody ever revokes.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "someone", "", true)
		if err != nil {
			t.Fatal(err)
		}

		if _, _, err := f.store.NewToken(ctx, person.ID, "too-long", nil, 48*time.Hour, 24*time.Hour); err == nil {
			t.Error("a token was minted past the ceiling")
		}
		token, _, err := f.store.NewToken(ctx, person.ID, "unstated", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !token.ExpiresAt.After(token.CreatedAt) {
			t.Error("a token with no lifetime stated does not expire")
		}
		if _, _, err := f.store.NewToken(ctx, person.ID, "  ", nil, time.Hour, 0); err == nil {
			t.Error("a token was minted with no name")
		}
	})
}

func TestARevokedTokenStopsWorking(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, secret := holder(t, f)

		token, err := f.store.TokenByName(ctx, person.ID, "scripting")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.RevokeToken(ctx, token.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ResolveToken(ctx, secret); err == nil {
			t.Error("a revoked token still worked")
		}

		// Kept rather than deleted, so what used it stays answerable.
		tokens, err := f.store.Tokens(ctx, person.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(tokens) != 1 || tokens[0].RevokedAt == nil {
			t.Errorf("a revoked token was not kept as revoked: %+v", tokens)
		}
	})
}

func TestOneKindOfCredentialIsNeverLookedUpAsAnother(t *testing.T) {
	// Every credential says which kind it is, so resolution dispatches rather
	// than trying each store in turn.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		_, secret := holder(t, f)
		key, keySecret, err := f.store.NewKey(ctx, "nightly", access.Scope{ProductID: f.products["sonic"]})
		if err != nil {
			t.Fatal(err)
		}
		_ = key

		if got := secret[:4]; got != access.TokenPrefix {
			t.Errorf("a personal token begins %q", got)
		}
		if got := keySecret[:4]; got != access.KeyPrefix {
			t.Errorf("a pipeline key begins %q", got)
		}
		// These two would hold with the prefixes deleted, because the stores
		// query different tables — so they pin the shape and not the dispatch.
		if _, err := f.store.ResolveKey(ctx, secret); err == nil {
			t.Error("a personal token resolved as a pipeline key")
		}
		if _, err := f.store.ResolveToken(ctx, keySecret); err == nil {
			t.Error("a pipeline key resolved as a personal token")
		}
	})
}

func TestATokenCannotMintOrWithdrawAnother(t *testing.T) {
	// Without this every limit on a token is one request deep: the holder asks
	// for a wider one and gets it, because minting resolves through the owner.
	// An administrator's narrowed token would mint one carrying administration.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		boss, err := f.store.Ensure(ctx, "boss", "", true)
		if err != nil {
			t.Fatal(err)
		}
		sonic := f.products["sonic"]
		_, narrow, err := f.store.NewToken(ctx, boss.ID, "narrow", &sonic, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}

		subject, err := f.store.ResolveToken(ctx, narrow)
		if err != nil {
			t.Fatal(err)
		}
		if subject.Admin {
			t.Fatal("a narrowed token carried administration")
		}
		if !subject.Delegated() {
			t.Error("a token did not arrive marked as a minted credential")
		}

		// And the same holds for one that was never narrowed: the limit is on
		// minting, not on how wide the token happens to be.
		_, wide, err := f.store.NewToken(ctx, boss.ID, "wide", nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		whole, err := f.store.ResolveToken(ctx, wide)
		if err != nil {
			t.Fatal(err)
		}
		if !whole.Delegated() {
			t.Error("an un-narrowed token did not arrive marked as a minted credential")
		}
	})
}

func TestTwoCredentialsMayNotShareAName(t *testing.T) {
	// A key's name is what an ingest records as having sent a scan, what
	// receipts are narrowed by, and what an administrator revokes. Two sharing
	// one makes each able to read the other's uploads, and makes a revocation
	// report success having withdrawn whichever row came back first.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, _, err := f.store.NewKey(ctx, "nightly", access.Scope{ProductID: f.products["sonic"]}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.NewKey(ctx, "nightly", access.Scope{ProductID: f.products["onie"]}); err == nil {
			t.Error("two keys were given one name")
		}

		person, err := f.store.Ensure(ctx, "someone", "", true)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.NewToken(ctx, person.ID, "scripting", nil, time.Hour, 0); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.NewToken(ctx, person.ID, "scripting", nil, time.Hour, 0); err == nil {
			t.Error("one person was given two tokens with one name")
		}
	})
}

func TestATokenDefaultsToWhateverTheCeilingAllows(t *testing.T) {
	// Somebody who states no lifetime asked to exceed nothing, so a deployment
	// with a short ceiling has to give them the ceiling rather than refuse
	// them while naming a limit they never mentioned.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "someone", "", true)
		if err != nil {
			t.Fatal(err)
		}
		token, _, err := f.store.NewToken(ctx, person.ID, "unstated", nil, 0, 24*time.Hour)
		if err != nil {
			t.Fatalf("a mint that stated no lifetime was refused: %v", err)
		}
		if got := token.ExpiresAt.Sub(token.CreatedAt); got != 24*time.Hour {
			t.Errorf("lasted %v, want the ceiling of 24h", got)
		}
	})
}
