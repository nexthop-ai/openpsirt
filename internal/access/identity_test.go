package access_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// authorized records somebody and the way they will sign in, which is what an
// administrator does before that person has ever arrived.
func authorized(t *testing.T, f *fixture, handle, username string) *access.Account {
	t.Helper()
	person, err := f.store.Ensure(t.Context(), handle, "", false)
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

		matched, err := f.store.MatchProvider(ctx, "1001", "alice")
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
		if _, err := f.store.MatchProvider(ctx, "1001", "alice"); err != nil {
			t.Fatal(err)
		}

		// Somebody else registers the name she used to hold.
		if _, err := f.store.MatchProvider(ctx, "2002", "alice"); err == nil {
			t.Fatal("somebody who took a released name was let in as its previous holder")
		}

		// And Alice, renamed, is still Alice.
		matched, err := f.store.MatchProvider(ctx, "1001", "alice-at-work")
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
		other, err := f.store.Ensure(ctx, "mallory", "", false)
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
			if _, err := f.store.MatchProvider(ctx, c.subject, c.username); err == nil {
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

			if _, err := f.store.MatchProvider(ctx, "00u1a2b3", "bhouse@example.com"); err != nil {
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
			matched, err := f.store.MatchProvider(ctx, "00u1a2b3", "bhouse@example.com")
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
