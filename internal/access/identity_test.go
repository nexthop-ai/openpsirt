package access_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// authorized records somebody and the way they will sign in, which is what an
// administrator does before that person has ever arrived.
func authorized(t *testing.T, f *fixture, handle, provider, username string) *access.Account {
	t.Helper()
	person, err := f.store.Ensure(t.Context(), handle, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.GrantRole(t.Context(), person.ID, f.products["sonic"], access.PublicRead); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Claim(t.Context(), person.ID, provider, username); err != nil {
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
		person := authorized(t, f, "alice", "github", "alice")

		matched, err := f.store.MatchProvider(ctx, "github", "1001", "alice")
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
	// The attack this whole shape exists to stop. A forge login can be
	// renamed and the name then registered by somebody else; matching on the
	// name would hand them the access it used to carry.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		alice := authorized(t, f, "alice", "github", "alice")

		// Alice signs in once, which pins her.
		if _, err := f.store.MatchProvider(ctx, "github", "1001", "alice"); err != nil {
			t.Fatal(err)
		}

		// Somebody else registers the name she used to hold.
		if _, err := f.store.MatchProvider(ctx, "github", "2002", "alice"); err == nil {
			t.Fatal("somebody who took a released name was let in as its previous holder")
		}

		// And Alice, renamed, is still Alice.
		matched, err := f.store.MatchProvider(ctx, "github", "1001", "alice-at-work")
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

func TestTheSameNameAtTwoProvidersIsTwoPeople(t *testing.T) {
	// A username is only unique within the provider that issued it. Treating
	// them as one person hands whoever can register the name at either
	// provider the access granted at the other.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		fromGitHub := authorized(t, f, "alice-github", "github", "alice")
		fromOkta := authorized(t, f, "alice-okta", "okta", "alice")
		if fromGitHub.ID == fromOkta.ID {
			t.Fatal("the fixture recorded one person")
		}

		// The same identifier at both, which is not far-fetched: plenty of
		// providers issue small numbers. If the provider were dropped from the
		// lookup these two would be one person, and whoever could register the
		// name at either would hold what was granted at the other.
		const shared = "1001"

		matched, err := f.store.MatchProvider(ctx, "github", shared, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if matched.ID != fromGitHub.ID {
			t.Error("a github sign-in matched the okta account")
		}
		matched, err = f.store.MatchProvider(ctx, "okta", shared, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if matched.ID != fromOkta.ID {
			t.Error("an okta sign-in matched the github account")
		}

		// Pinned separately, so neither took the other's identifier.
		for _, who := range []struct {
			name   string
			person *access.Account
		}{{"github", fromGitHub}, {"okta", fromOkta}} {
			identities, err := f.store.Identities(ctx, who.person.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(identities) != 1 || identities[0].Provider != who.name {
				t.Errorf("%s resolved to %+v", who.name, identities)
			}
		}
	})
}

func TestOneNameAtOneProviderBelongsToOnePerson(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		authorized(t, f, "alice", "github", "alice")
		other, err := f.store.Ensure(ctx, "mallory", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.Claim(ctx, other.ID, "github", "alice"); err == nil {
			t.Error("two people were authorized under one name at one provider")
		}
	})
}

func TestSomebodyNobodyAuthorizedIsRefusedWhateverTheyPresent(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		authorized(t, f, "alice", "github", "alice")

		for _, c := range []struct{ provider, subject, username string }{
			{"github", "9999", "mallory"},
			{"github", "", "mallory"},
			{"okta", "1001", "alice"},
			{"", "1001", "alice"},
			{"github", "1001", ""},
		} {
			if _, err := f.store.MatchProvider(ctx, c.provider, c.subject, c.username); err == nil {
				t.Errorf("%+v was let in", c)
			}
		}
	})
}

func TestAProxyHasNoIdentifierBeyondTheNameItAsserts(t *testing.T) {
	// A property of the arrangement rather than a shortcut: the proxy asserts
	// a username on every request and there is nothing else to match on. A
	// deployment trusting it has already accepted that what it says is who
	// somebody is.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person := authorized(t, f, "someone", access.ProxyProvider, "someone")

		matched, err := f.store.MatchProvider(ctx, access.ProxyProvider, "someone", "someone")
		if err != nil {
			t.Fatalf("the proxy path refused somebody authorized: %v", err)
		}
		if matched.ID != person.ID {
			t.Error("matched somebody else")
		}
	})
}
