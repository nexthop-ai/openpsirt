// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// authorized records somebody and the way they will sign in, which is what an
// administrator does before that person has ever arrived.
func authorized(t *testing.T, f *fixture, handle, username string) *access.Account {
	t.Helper()
	person, err := f.store.Ensure(t.Context(), handle, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.GrantRole(t.Context(), person.ID, f.products["sonic"], access.PublicRead); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Claim(t.Context(), person.ID, username); err != nil {
		t.Fatal(err)
	}
	return person
}

func TestAnAuthorizationIsRedeemedByNameAndThenPinnedToTheIdentifier(t *testing.T) {
	// An administrator can only type the name. The provider's own identifier
	// is not knowable until the person actually arrives, so authorizing in
	// advance is expressed in the moving name and pinned at first use.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person := authorized(t, f, "alice", "alice")

		matched, err := f.store.MatchProvider(ctx, "okta", "1001", "alice")
		if err != nil {
			t.Fatalf("somebody authorized in advance was refused: %v", err)
		}
		if matched.ID != person.ID {
			t.Errorf("matched somebody else")
		}

		identities, err := f.store.Identities(ctx, person.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(identities) != 1 || identities[0].Subject == nil || *identities[0].Subject != "1001" {
			t.Fatalf("the identifier was not pinned: %+v", identities)
		}
		if identities[0].BoundAt == nil {
			t.Error("nothing records when it was pinned")
		}
	})
}

func TestSomebodyWhoTakesAReleasedNameIsNotTheirPredecessor(t *testing.T) {
	// The attack the identifier exists to stop. A forge login can be renamed
	// and the name then registered by somebody else; matching on the name
	// would hand them the access it used to carry.
	//
	// Unaffected by dropping the provider from the lookup: it is the
	// identifier that answers this, and the identifier is still bound.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		alice := authorized(t, f, "alice", "alice")

		// Alice signs in once, which pins her.
		if _, err := f.store.MatchProvider(ctx, "okta", "1001", "alice"); err != nil {
			t.Fatal(err)
		}

		// Somebody else registers the name she used to hold.
		if _, err := f.store.MatchProvider(ctx, "okta", "2002", "alice"); err == nil {
			t.Fatal("somebody who took a released name was let in as its previous holder")
		}

		// And Alice, renamed, is still Alice.
		matched, err := f.store.MatchProvider(ctx, "okta", "1001", "alice-at-work")
		if err != nil {
			t.Fatalf("somebody who renamed themselves was refused: %v", err)
		}
		if matched.ID != alice.ID {
			t.Error("a rename made somebody into somebody else")
		}
		// The name that is read follows, because it is only a label.
		identities, err := f.store.Identities(ctx, alice.ID)
		if err != nil {
			t.Fatal(err)
		}
		if identities[0].Username != "alice-at-work" {
			t.Errorf("the name shown is still %q", identities[0].Username)
		}
	})
}

func TestOneNameBelongsToOnePerson(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		authorized(t, f, "alice", "alice")
		other, err := f.store.Ensure(ctx, "mallory", "Mallory", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.Claim(ctx, other.ID, "alice"); err == nil {
			t.Error("two people were authorized under one name")
		}
	})
}

func TestSomebodyNobodyAuthorizedIsRefusedWhateverTheyPresent(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		authorized(t, f, "alice", "alice")

		for _, c := range []struct{ subject, username string }{
			{"9999", "mallory"},
			{"", "mallory"},
			// No identifier at all, for a name that does exist. A provider
			// naming somebody without one leaves the authorization redeemable
			// by name forever, which is the matching the identifier replaces.
			{"", "alice"},
			{"1001", ""},
		} {
			if _, err := f.store.MatchProvider(ctx, "okta", c.subject, c.username); err == nil {
				t.Errorf("%+v was let in", c)
			}
		}

		if _, err := f.store.MatchProxy(ctx, "mallory"); err == nil {
			t.Error("the proxy path let in somebody nobody authorized")
		}
	})
}

func TestTheProxyAssertsANameAndBindsNothing(t *testing.T) {
	// A property of the arrangement rather than a shortcut: the proxy asserts
	// a username on every request and has nothing else to offer. A deployment
	// trusting it has already accepted that what it says is who somebody is.
	//
	// Binding a made-up identifier here is what used to keep the two paths in
	// separate rows, and separate rows are what made one human two accounts.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person := authorized(t, f, "someone", "someone")

		matched, err := f.store.MatchProxy(ctx, "someone")
		if err != nil {
			t.Fatalf("the proxy path refused somebody authorized: %v", err)
		}
		if matched.ID != person.ID {
			t.Error("matched somebody else")
		}

		identities, err := f.store.Identities(ctx, person.ID)
		if err != nil {
			t.Fatal(err)
		}
		if identities[0].Subject != nil {
			t.Errorf("the proxy bound an identifier: %q", *identities[0].Subject)
		}
	})
}

func TestOneUsernameIsOnePersonWhicheverWayTheyArrive(t *testing.T) {
	// The defect that settled this. Scoping an identity by the path it
	// arrived on made backdoor access and provider sign-in two accounts for
	// one human — which split administration from the account being signed in
	// as, and let one person be both the proposer and the approver of a
	// dismissal (REQ-41).
	//
	// Run both ways round, because the order somebody first arrives in is not
	// something a deployment controls.
	t.Run("provider first, then the proxy", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			ctx := t.Context()
			person := authorized(t, f, "bhouse@example.com", "bhouse@example.com")

			if _, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "bhouse@example.com"); err != nil {
				t.Fatalf("the provider refused somebody authorized: %v", err)
			}
			// The recovery path has to work on the day it is needed, and by
			// then the provider has usually bound its identifier already. A
			// proxy arrival is not measured against it.
			matched, err := f.store.MatchProxy(ctx, "bhouse@example.com")
			if err != nil {
				t.Fatalf("a bound identifier locked out the proxy: %v", err)
			}
			if matched.ID != person.ID {
				t.Error("the proxy reached a different person than the provider")
			}
		})
	})

	t.Run("proxy first, then the provider", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			ctx := t.Context()
			person := authorized(t, f, "bhouse@example.com", "bhouse@example.com")

			if _, err := f.store.MatchProxy(ctx, "bhouse@example.com"); err != nil {
				t.Fatalf("the proxy refused somebody authorized: %v", err)
			}
			matched, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "bhouse@example.com")
			if err != nil {
				t.Fatalf("the provider was refused after a proxy arrival: %v", err)
			}
			if matched.ID != person.ID {
				t.Error("the provider reached a different person than the proxy")
			}

			// And the provider fills in what the proxy left empty, so the
			// rename protection is in force from that sign-in onward.
			identities, err := f.store.Identities(ctx, person.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(identities) != 1 {
				t.Fatalf("one person has %d identities", len(identities))
			}
			if identities[0].Subject == nil || *identities[0].Subject != "00u1a2b3" {
				t.Fatalf("the provider did not bind its identifier: %+v", identities[0])
			}
		})
	})
}

func TestAnIdentifierIsReadOnlyAsTheProviderThatIssuedItMeantIt(t *testing.T) {
	// One provider is configured at a time (REQ-41), and that is a rule across
	// time rather than at one instant. A deployment pointed at a second
	// provider would read identifiers the first issued as though this one had
	// issued them — and two providers do not agree on what any identifier
	// names, so whoever holds that string at the new provider redeems roles
	// granted to somebody else entirely.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		authorized(t, f, "alice", "alice")

		// Redeemed and pinned under the provider configured at the time.
		if _, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "alice"); err != nil {
			t.Fatalf("the authorization was not redeemed: %v", err)
		}

		// The same identifier, arriving from somewhere else. It is a
		// different namespace and so a different person.
		if _, err := f.store.MatchProvider(ctx, "keycloak", "00u1a2b3", "alice"); err == nil {
			t.Error("an identifier issued by one provider was accepted from another")
		}

		// And the name is not redeemable a second time to get around that:
		// the row is pinned, and to an identifier nothing here can still
		// interpret.
		if _, err := f.store.MatchProvider(ctx, "keycloak", "kc-99", "alice"); err == nil {
			t.Error("a pinned name was redeemed again after the provider changed")
		}
	})
}

func TestAnIdentifierWithNoIssuerNamesNobody(t *testing.T) {
	// A subject is meaningless without the provider that issued it, so an
	// arrival that cannot say where its identifier came from is refused
	// rather than bound to whatever is configured.
	each(t, func(t *testing.T, f *fixture) {
		authorized(t, f, "alice", "alice")
		if _, err := f.store.MatchProvider(t.Context(), "", "1001", "alice"); err == nil {
			t.Error("an identifier with no issuer was bound to an authorization")
		}
	})
}

func TestWhichProvidersHaveBoundAnIdentity(t *testing.T) {
	// The startup check's input. An authorization nobody has redeemed
	// binds nothing, so it names no provider and does not stop a deployment
	// that has not yet been signed in to from changing provider.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		authorized(t, f, "alice", "alice")

		bound, err := f.store.BoundProviders(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(bound) != 0 {
			t.Errorf("an unredeemed authorization names %v", bound)
		}

		if _, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "alice"); err != nil {
			t.Fatal(err)
		}
		bound, err = f.store.BoundProviders(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(bound) != 1 || bound[0] != "okta" {
			t.Errorf("the bound providers read as %v, want just okta", bound)
		}
	})
}

func TestAnAuthorizationNobodyRedeemedStopsBeingRedeemable(t *testing.T) {
	// The window where a name rather than an identifier decides who gets a set
	// of roles. An administrator writes the authorization before the person
	// has ever arrived, so it is matched by the name they typed — and left
	// open for ever, it waits for whoever turns up holding that name at the
	// provider, which on a provider where people choose their own name is
	// anybody who wants those roles.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "alice", "Alice", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		// Written with a window that has already run out by the time anybody
		// arrives holding the name.
		if err := f.store.ClaimingWithin(time.Nanosecond).Claim(ctx, person.ID, "alice"); err != nil {
			t.Fatal(err)
		}

		if _, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "alice"); err == nil {
			t.Error("an authorization nobody redeemed inside its window was still redeemed")
		}
	})
}

func TestAnAuthorizationIsRedeemableInsideItsWindow(t *testing.T) {
	// The other half, and the one that matters more: bounding the window must
	// not make an ordinary first sign-in fail. Somebody authorized ahead of a
	// start date arrives days later and is still who was authorized.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person := authorized(t, f, "alice", "alice")

		matched, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "alice")
		if err != nil {
			t.Fatalf("an authorization inside its window was refused: %v", err)
		}
		if matched.ID != person.ID {
			t.Errorf("the authorization was redeemed by person %d, want %d", matched.ID, person.ID)
		}
	})
}

func TestAProxyLetsSomebodyInWhileTheProviderIsUnreachable(t *testing.T) {
	// The way back in when the provider is down. A reverse proxy asserts the
	// name and the deployment runs with no provider configured at all, which
	// is the arrangement the trusted header exists for.
	//
	// A pinned identifier does not refuse it, and must not: the mismatch
	// refusal protects a name that moved between people at the provider, and
	// a deployment trusting the header has already granted whatever sets it
	// the power to claim to be anybody.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person := authorized(t, f, "alice", "alice")
		if _, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "alice"); err != nil {
			t.Fatalf("the first sign-in did not pin: %v", err)
		}

		got, err := f.store.MatchProxy(ctx, "alice")
		if err != nil {
			t.Fatalf("somebody bound to a provider cannot come in by proxy: %v", err)
		}
		if got.ID != person.ID {
			t.Errorf("the proxy resolved to person %d, want %d", got.ID, person.ID)
		}
	})
}

func TestChangingProviderIsUnbindThenSwitch(t *testing.T) {
	// The provider change this refuses to do silently, done deliberately.
	//
	// Unbinding leaves the authorization standing and clears what the old
	// provider issued — both halves of it. Leaving the provider behind would
	// make the startup check read withdrawn bindings as bindings nobody
	// withdrew, so unbinding everybody would still not let the new provider
	// start, and the way back in would be editing the database by hand.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person := authorized(t, f, "alice", "alice")
		if _, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "alice"); err != nil {
			t.Fatal(err)
		}
		if bound, err := f.store.BoundProviders(ctx); err != nil || len(bound) != 1 {
			t.Fatalf("the bound providers read as %v (%v)", bound, err)
		}

		if err := f.store.UnbindIdentifier(ctx, person.ID); err != nil {
			t.Fatal(err)
		}

		// Nothing is bound now, so a deployment configured for somewhere else
		// starts rather than refusing.
		bound, err := f.store.BoundProviders(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(bound) != 0 {
			t.Errorf("unbinding left %v behind, which still refuses the new provider", bound)
		}

		// And the authorization is redeemable again, under the new provider,
		// by whoever arrives holding the name — which is what it was before
		// anybody signed in.
		matched, err := f.store.MatchProvider(ctx, "entra", "aad-9f2c", "alice")
		if err != nil {
			t.Fatalf("the authorization was not redeemable under the new provider: %v", err)
		}
		if matched.ID != person.ID {
			t.Errorf("the new provider redeemed person %d, want %d", matched.ID, person.ID)
		}
	})
}

func TestAuthorizingSomebodyAgainRestartsTheirWindow(t *testing.T) {
	// The window is written when an authorization is, and without this it
	// could be written once and never again: an authorization nobody redeemed
	// would be un-reopenable by any act at all.
	//
	// The administrators named in configuration are the sharp end. Their
	// authorization is written again at every start, so a window that never
	// restarted would take the deployment's own way back in away on the day
	// it lapsed — with nothing logged, and the deployment still reporting
	// that somebody can administer it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "alice", "Alice", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.ClaimingWithin(time.Nanosecond).Claim(ctx, person.ID, "alice"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "alice"); err == nil {
			t.Fatal("the window did not lapse, so this test pins nothing")
		}

		// Written again, the way a start writes it for a named administrator.
		if err := f.store.Claim(ctx, person.ID, "alice"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "alice"); err != nil {
			t.Errorf("authorizing somebody again left them unable to sign in: %v", err)
		}
	})
}

func TestUnbindingMakesAnAuthorizationRedeemableAgain(t *testing.T) {
	// Unbinding says the authorization is standing and redeemable again. A
	// row that came back carrying a window which lapsed while it was bound is
	// redeemable by nobody, which would make a provider change a way to lock
	// out everybody who had signed in more than a window ago.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person := authorized(t, f, "alice", "alice")
		if _, err := f.store.MatchProvider(ctx, "okta", "00u1a2b3", "alice"); err != nil {
			t.Fatal(err)
		}
		// Bound well inside the window, then unbound long after it would have
		// lapsed had anybody been counting.
		lapsed := f.store.ClaimingWithin(time.Nanosecond)
		if err := lapsed.UnbindIdentifier(ctx, person.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.MatchProvider(ctx, "entra", "aad-9f2c", "alice"); err == nil {
			t.Log("the window this store unbound with was tiny, so it lapsed at once")
		}

		// With the ordinary window it is redeemable again, which is what
		// unbinding promises.
		if err := f.store.UnbindIdentifier(ctx, person.ID); err != nil {
			t.Fatal(err)
		}
		matched, err := f.store.MatchProvider(ctx, "entra", "aad-9f2c", "alice")
		if err != nil {
			t.Fatalf("an unbound authorization was not redeemable again: %v", err)
		}
		if matched.ID != person.ID {
			t.Errorf("redeemed person %d, want %d", matched.ID, person.ID)
		}
	})
}

func TestAProxyChargesTheSameWindowAsAProvider(t *testing.T) {
	// The window is about a name, and the proxy path is the one where a name
	// alone decides who gets the roles. Charged on the provider path only, an
	// authorization nobody redeemed stayed redeemable for ever through the
	// header — which is the wider of the two doors, not the narrower.
	//
	// The deployment's own way back in is not what this closes: an
	// administrator named in configuration is authorized again at every
	// start, which restarts the window.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "alice", "Alice", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		if err := f.store.ClaimingWithin(time.Nanosecond).Claim(ctx, person.ID, "alice"); err != nil {
			t.Fatal(err)
		}

		if _, err := f.store.MatchProxy(ctx, "alice"); err == nil {
			t.Error("an authorization nobody redeemed inside its window was redeemed by proxy")
		}

		// And authorizing again reopens it on this path as well.
		if err := f.store.Claim(ctx, person.ID, "alice"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.MatchProxy(ctx, "alice"); err != nil {
			t.Errorf("a reopened authorization was refused by proxy: %v", err)
		}
	})
}
