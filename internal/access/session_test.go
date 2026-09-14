package access_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// signedIn grants somebody a role and starts a session for them, which is the
// state every test here begins from.
func signedIn(t *testing.T, f *fixture, identity string) (*access.Account, *access.Issued) {
	t.Helper()
	ctx := t.Context()
	person, err := f.store.Ensure(ctx, identity, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
		t.Fatal(err)
	}
	issued, err := f.store.StartSession(ctx, person.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return person, issued
}

func TestASessionStandsForWhoeverItWasIssuedTo(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		person, issued := signedIn(t, f, "someone")

		subject, session, err := f.store.ResolveSession(t.Context(), issued.Token)
		if err != nil {
			t.Fatalf("resolving a session just issued: %v", err)
		}
		if subject.Identity != "someone" || subject.Kind != access.Person {
			t.Errorf("resolved to %+v", subject)
		}
		if session.PersonID != person.ID {
			t.Errorf("session belongs to %d, want %d", session.PersonID, person.ID)
		}
		if !subject.Reads(access.Public, f.products["sonic"]) {
			t.Error("a session reached none of what its owner holds")
		}
	})
}

func TestWhatASessionReachesIsReadNowRatherThanRemembered(t *testing.T) {
	// A session establishes who is asking, never what they may do. Otherwise a
	// role withdrawn — by an admin, or by a group membership that went away —
	// would keep working until the session expired, which is the whole window
	// group binding is supposed to bound.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, issued := signedIn(t, f, "someone")

		if err := f.store.GrantRole(ctx, person.ID, f.products["onie"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		subject, _, err := f.store.ResolveSession(ctx, issued.Token)
		if err != nil {
			t.Fatal(err)
		}
		if !subject.Reads(access.Public, f.products["onie"]) {
			t.Error("a role granted after sign-in was not reached by the session")
		}

		if err := f.store.Withdraw(ctx, person.ID, f.products["onie"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		subject, _, err = f.store.ResolveSession(ctx, issued.Token)
		if err != nil {
			t.Fatal(err)
		}
		if subject.Reads(access.Public, f.products["onie"]) {
			t.Error("a role withdrawn after sign-in was still reached by the session")
		}
	})
}

func TestAnUnstatedLifetimeTakesTheDefault(t *testing.T) {
	// StartSession takes a lifetime from configuration, and configuration is
	// edited by hand. Zero and anything below it are read as "nobody said",
	// which lands on the default rather than on a session that never ends.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "someone", "Someone", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, person.ID, f.products["sonic"], access.PublicRead); err != nil {
			t.Fatal(err)
		}
		for _, stated := range []time.Duration{0, -time.Minute, -time.Hour * 1000} {
			issued, err := f.store.StartSession(ctx, person.ID, stated)
			if err != nil {
				t.Fatal(err)
			}
			got := issued.Session.ExpiresAt.Sub(issued.Session.CreatedAt)
			if got != access.DefaultSessionLifetime {
				t.Errorf("a lifetime of %v produced %v, want the default %v",
					stated, got, access.DefaultSessionLifetime)
			}
		}
	})
}

func TestSigningOutStopsTheSessionAtOnce(t *testing.T) {
	// Sessions are stored rather than held in a process's memory so that this
	// works whichever copy of the application answers next.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		_, issued := signedIn(t, f, "someone")

		if err := f.store.EndSession(ctx, issued.Session.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.ResolveSession(ctx, issued.Token); err == nil {
			t.Error("a session kept working after it was ended")
		}
	})
}

func TestCuttingSomebodyOffEndsEverySessionTheyHold(t *testing.T) {
	// Signing out one browser is not the same act as withdrawing access, and
	// the second is the one relied on when somebody leaves.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, first := signedIn(t, f, "someone")
		second, err := f.store.StartSession(ctx, person.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}

		if err := f.store.EndSessionsFor(ctx, person.ID); err != nil {
			t.Fatal(err)
		}
		for name, token := range map[string]string{"first": first.Token, "second": second.Token} {
			if _, _, err := f.store.ResolveSession(ctx, token); err == nil {
				t.Errorf("the %s session survived", name)
			}
		}
	})
}

func TestASessionTokenIsNotRecoverableFromWhatIsStored(t *testing.T) {
	// The same rule as a pipeline's key: a store that can hand back what it
	// holds hands over every live session with a copy of the database.
	each(t, func(t *testing.T, f *fixture) {
		_, issued := signedIn(t, f, "someone")
		if issued.Session.TokenHash == issued.Token {
			t.Error("the session token is stored as it was handed out")
		}
		if issued.Token == "" || issued.CSRF == "" {
			t.Fatal("a session was issued without one of its two secrets")
		}
		if issued.Token == issued.CSRF {
			t.Error("the cookie and the value echoed against it are the same secret")
		}
	})
}

func TestTheValueEchoedAgainstASessionHasToBeThatSessions(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, mine := signedIn(t, f, "someone")
		theirs, err := f.store.StartSession(ctx, person.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}

		if !mine.Session.MatchesCSRF(mine.CSRF) {
			t.Error("a session rejected its own value")
		}
		if mine.Session.MatchesCSRF(theirs.CSRF) {
			t.Error("a session accepted another session's value")
		}
		if mine.Session.MatchesCSRF("") {
			t.Error("a session accepted an empty value")
		}
	})
}

func TestAStrangersTokenReachesNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		for _, token := range []string{"", "not-a-token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
			if _, _, err := f.store.ResolveSession(t.Context(), token); err == nil {
				t.Errorf("%q resolved to somebody", token)
			}
		}
	})
}

// TestASignInHasACeiling pins the window a session is.
//
// Group membership is read at sign-in and never again, so the lifetime *is*
// how long somebody removed from a privileged provider group still holds what
// that group gave them. It was clamped up from nothing and accepted anything
// above it, so an administrator setting 8760h made every browser sign-in last
// a year — while a personal token, the other thing somebody holds for a long
// time, has had two ceilings all along.
func TestASignInHasACeiling(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		person, err := f.store.Ensure(ctx, "ana", "", false)
		if err != nil {
			t.Fatal(err)
		}

		// Nothing asked for takes the default, which is the ordinary case.
		issued, err := f.store.StartSession(ctx, person.ID, 0)
		if err != nil {
			t.Fatal(err)
		}
		if issued.Session.ExpiresAt.Sub(issued.Session.CreatedAt) != access.DefaultSessionLifetime {
			t.Errorf("a sign-in asking for nothing lasts %s",
				issued.Session.ExpiresAt.Sub(issued.Session.CreatedAt))
		}

		// The ceiling itself is allowed.
		if _, err := f.store.StartSession(ctx, person.ID, access.MaxSessionLifetime); err != nil {
			t.Errorf("a sign-in at the ceiling was refused: %v", err)
		}

		// And a year is refused, told rather than quietly shortened: an
		// administrator who typed it should hear the limit now.
		_, err = f.store.StartSession(ctx, person.ID, 365*24*time.Hour)
		if err == nil {
			t.Fatal("a sign-in lasting a year was issued")
		}
		if !strings.Contains(err.Error(), access.MaxSessionLifetime.String()) {
			t.Errorf("the refusal does not say the limit: %v", err)
		}
	})
}
