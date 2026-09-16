package access_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// holder is somebody with a role and a token of their own.
func holder(t *testing.T, f *fixture) (*access.Account, string) {
	t.Helper()
	ctx := t.Context()
	person, err := f.store.Ensure(ctx, "someone", "Someone", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
		t.Fatal(err)
	}
	if err := f.store.GrantRole(ctx, person.ID, f.products["onie"], access.PublicRead); err != nil {
		t.Fatal(err)
	}
	_, secret, err := f.store.NewToken(ctx, person.ID, "scripting", nil, nil, time.Hour, 0)
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
		_, narrowed, err := f.store.NewToken(ctx, person.ID, "sonic-only", &sonic, nil, time.Hour, 0)
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
		person, err := f.store.Ensure(ctx, "an-admin", "An Admin", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}
		sonic := f.products["sonic"]
		_, secret, err := f.store.NewToken(ctx, person.ID, "narrow", &sonic, nil, time.Hour, 0)
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
		person, err := f.store.Ensure(ctx, "someone", "Someone", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}

		if _, _, err := f.store.NewToken(ctx, person.ID, "too-long", nil, nil, 48*time.Hour, 24*time.Hour); err == nil {
			t.Error("a token was minted past the ceiling")
		}
		token, _, err := f.store.NewToken(ctx, person.ID, "unstated", nil, nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !token.ExpiresAt.After(token.CreatedAt) {
			t.Error("a token with no lifetime stated does not expire")
		}
		if _, _, err := f.store.NewToken(ctx, person.ID, "  ", nil, nil, time.Hour, 0); err == nil {
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
		boss, err := f.store.Ensure(ctx, "boss", "Boss", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}
		sonic := f.products["sonic"]
		_, narrow, err := f.store.NewToken(ctx, boss.ID, "narrow", &sonic, nil, time.Hour, 0)
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
		_, wide, err := f.store.NewToken(ctx, boss.ID, "wide", nil, nil, time.Hour, 0)
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

		person, err := f.store.Ensure(ctx, "someone", "Someone", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.NewToken(ctx, person.ID, "scripting", nil, nil, time.Hour, 0); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.NewToken(ctx, person.ID, "scripting", nil, nil, time.Hour, 0); err == nil {
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
		person, err := f.store.Ensure(ctx, "someone", "Someone", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}
		token, _, err := f.store.NewToken(ctx, person.ID, "unstated", nil, nil, 0, 24*time.Hour)
		if err != nil {
			t.Fatalf("a mint that stated no lifetime was refused: %v", err)
		}
		if got := token.ExpiresAt.Sub(token.CreatedAt); got != 24*time.Hour {
			t.Errorf("lasted %v, want the ceiling of 24h", got)
		}
	})
}

// TestANarrowedTokenIsStillTheSamePerson pins what narrowing takes away and
// what it must not.
//
// It was written as a fresh Subject carrying five fields, so everything else
// went silently: who somebody is in the assignable space, the teams they are
// on, and the cases they were brought into. None of those is a per-product
// fact. Through such a token every "assigned to me" surface answered empty and
// taking an unowned finding for yourself was refused with a message saying you
// were giving work to somebody else — while the same acts worked through the
// same person's session.
func TestANarrowedTokenIsStillTheSamePerson(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		here := f.products["sonic"]
		elsewhere := f.products["onie"]

		person, err := f.store.Ensure(ctx, "ana", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, here, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, elsewhere, access.PublicRead); err != nil {
			t.Fatal(err)
		}
		team, err := f.store.DeclareTeam(ctx, "kernel", "Kernel")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.AddToTeam(ctx, team.ID, person.ID, person.ID); err != nil {
			t.Fatal(err)
		}
		// Brought into one case here, and one over there. Real issues,
		// because a case grant points at one.
		issues, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-0001", Severity: "high"},
			{Identifier: "CVE-2026-0002", Severity: "high"},
		})
		if err != nil {
			t.Fatal(err)
		}
		mine, theirs := issues["CVE-2026-0001"], issues["CVE-2026-0002"]
		if err := f.store.AddToCase(ctx, here, mine, person.ID, person.ID); err != nil {
			t.Fatal(err)
		}
		if err := f.store.AddToCase(ctx, elsewhere, theirs, person.ID, person.ID); err != nil {
			t.Fatal(err)
		}

		_, secret, err := f.store.NewToken(ctx, person.ID, "pinned", &here, nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		narrowed, err := f.store.ResolveToken(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		whole, err := f.store.Resolve(ctx, "ana")
		if err != nil {
			t.Fatal(err)
		}

		// Who they are does not change because a credential was pinned.
		if narrowed.Party() != whole.Party() || narrowed.Party() == 0 {
			t.Errorf("a narrowed token is party %d and the person is party %d",
				narrowed.Party(), whole.Party())
		}
		if len(narrowed.Mine()) != len(whole.Mine()) {
			t.Errorf("a narrowed token counts as %v and the person as %v",
				narrowed.Mine(), whole.Mine())
		}
		// The case on the product it is pinned to is reached; the one
		// elsewhere is not, for the same reason the roles elsewhere are not.
		if !narrowed.OnCase(here, mine) {
			t.Error("a narrowed token cannot open the case it was brought into")
		}
		if narrowed.OnCase(elsewhere, theirs) {
			t.Error("a token pinned to one product reaches a case in another")
		}

		// And it is still narrower than its owner, which is the whole point.
		if narrowed.Reads(access.Public, elsewhere) {
			t.Error("a token pinned to one product reads another")
		}
		if narrowed.Admin {
			t.Error("a narrowed token carries administration")
		}
		if !narrowed.Reads(access.Public, here) {
			t.Error("a narrowed token does not read the product it is pinned to")
		}
	})
}

// TestATokenStopsCarryingARoleAGroupStoppedDeriving holds the line that a grant
// a group derived has to have been derived recently to still grant anything
// through a personal token.
//
// Membership is read at sign-in, and a sign-in replaces somebody's derived
// grants whole — so a browser's are never older than its session. A token never
// signs in. It resolves through its owner and reads whatever their last sign-in
// wrote, so without a bound a group somebody left went on granting them roles
// through that token until they next signed in, which for somebody who has gone
// is never.
//
// The window is the session lifetime, which is the same one the access document
// already names as how long a role a group withdrew can still be held. It was
// true of a browser and false of a token.
//
// What an administrator assigned is untouched. That is a standing decision
// rather than a reading of somebody's membership, and it does not go off.
func TestATokenStopsCarryingARoleAGroupStoppedDeriving(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "scripted", "Scripted", nil)
		if err != nil {
			t.Fatal(err)
		}
		// Assigned on one product and derived on the other, so that what the
		// window takes away is distinguishable from the token simply failing.
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		derived := access.Grant{
			PersonID: person.ID, ProductID: f.products["onie"],
			Role: access.PublicRead, Source: access.Derived, Active: true,
			// Older than the window below, which is what a person who stopped
			// signing in leaves behind.
			CreatedAt: time.Now().UTC().Add(-48 * time.Hour),
		}
		if _, err := f.db.DB.NewInsert().Model(&derived).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		_, secret, err := f.store.NewToken(ctx, person.ID, "scripting", nil, nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}

		bounded := f.store.DerivingWithin(func(context.Context) time.Duration { return 24 * time.Hour })
		subject, err := bounded.ResolveToken(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		if subject.Reads(access.Public, f.products["onie"]) {
			t.Error("a token carried a role no group has derived since before the window")
		}
		if !subject.Reads(access.Public, f.products["sonic"]) {
			t.Error("a token lost a role an administrator assigned, which does not go off")
		}

		// And the same grant, derived inside the window, still grants.
		if _, err := f.db.DB.NewUpdate().Model((*access.Grant)(nil)).
			Set("created_at = ?", time.Now().UTC()).
			Where("id = ?", derived.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		subject, err = bounded.ResolveToken(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		if !subject.Reads(access.Public, f.products["onie"]) {
			t.Error("a freshly derived role granted nothing, so the window refuses everything")
		}
	})
}

// TestATokenCarriesOnlyTheRolesItWasMintedFor holds the line that a token can
// be narrowed to some of what its owner may do, and that the narrowing is an
// intersection rather than a grant.
//
// A credential handed to a script that only reads should not also be able to
// triage, and until it could be narrowed the only way to get one was to hold
// nothing else yourself. Minting it needs no second person precisely because it
// can only ever reach less: naming a role its owner does not hold reaches
// nothing through it.
func TestATokenCarriesOnlyTheRolesItWasMintedFor(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "scripted", "Scripted", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range []access.Role{access.PublicRead, access.PublicTriage} {
			if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], role); err != nil {
				t.Fatal(err)
			}
		}

		for _, c := range []struct {
			what    string
			holds   []access.Role
			reads   bool
			triages bool
		}{
			{"narrowed to reading", []access.Role{access.PublicRead}, true, false},
			{"naming both", []access.Role{access.PublicRead, access.PublicTriage}, true, true},
			{"naming none", nil, true, true},
			// Named but not held. The intersection is empty on this product,
			// which is the property that makes minting safe: a token cannot
			// ask for more than its owner has.
			{"naming a role its owner does not hold", []access.Role{access.Approver}, false, false},
		} {
			_, secret, err := f.store.NewToken(ctx, person.ID, c.what, nil, c.holds, time.Hour, 0)
			if err != nil {
				t.Fatalf("%s: %v", c.what, err)
			}
			subject, err := f.store.ResolveToken(ctx, secret)
			if err != nil {
				t.Fatalf("%s: %v", c.what, err)
			}
			if got := subject.Reads(access.Public, f.products["sonic"]); got != c.reads {
				t.Errorf("a token %s reads the product: %v, want %v", c.what, got, c.reads)
			}
			if got := subject.Triages(access.Public, f.products["sonic"]); got != c.triages {
				t.Errorf("a token %s triages the product: %v, want %v", c.what, got, c.triages)
			}
		}
	})
}

// TestAReadingTokenCannotWriteOnItsOwnersCase holds the line that narrowing a
// token to reading takes the write half of a case grant with it.
//
// A case grant is enough to write on its own — a note, an attachment and a
// decision each accept it in place of a triage role, because somebody brought
// onto an embargoed issue is brought on to work it. Keeping the grant whole
// through a narrowing meant a credential labelled "reading only" could still
// record a decision on the embargoed issue it was minted for.
//
// The read half stays, which is the reason it is not simply dropped: a token
// that cannot read the one case it exists for is no use to anybody.
func TestAReadingTokenCannotWriteOnItsOwnersCase(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "collab", "Collab", nil)
		if err != nil {
			t.Fatal(err)
		}
		// A case and nothing else, which is the shape that writes without a
		// role. A reading role beside it so the narrowing has something to
		// keep.
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		issues, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx, []finding.Named{
			{Identifier: "SONIC-2026-8100", Severity: "high"},
		})
		if err != nil {
			t.Fatal(err)
		}
		issue := issues["SONIC-2026-8100"]
		if err := f.store.AddToCase(ctx, f.products["sonic"], issue, person.ID, person.ID); err != nil {
			t.Fatal(err)
		}

		for _, c := range []struct {
			what  string
			holds []access.Role
			acts  bool
		}{
			{"carrying everything", nil, true},
			{"narrowed to reading", []access.Role{access.PublicRead}, false},
			{"narrowed to triage", []access.Role{access.PublicTriage}, true},
		} {
			_, secret, err := f.store.NewToken(ctx, person.ID, c.what, nil, c.holds, time.Hour, 0)
			if err != nil {
				t.Fatalf("%s: %v", c.what, err)
			}
			subject, err := f.store.ResolveToken(ctx, secret)
			if err != nil {
				t.Fatalf("%s: %v", c.what, err)
			}
			// The read half is there whichever way it was narrowed.
			if !subject.OnCase(f.products["sonic"], issue) {
				t.Errorf("a token %s cannot read the case it was minted for", c.what)
			}
			if got := subject.OnCaseToAct(f.products["sonic"], issue); got != c.acts {
				t.Errorf("a token %s writes on the case: %v, want %v", c.what, got, c.acts)
			}
		}
	})
}
