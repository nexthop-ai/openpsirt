package access

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// atClock is a store whose sense of now a test moves, because a session
// expires by time passing rather than by being born expired — a lifetime of
// zero or less is taken as "unstated" and becomes the default, so there is no
// way to ask for one that has already run out.
func atClock(t *testing.T, db *database.DB, at *time.Time) (*Store, int64) {
	t.Helper()
	dbtest.Reset(t, db)

	// An administrator, so that no product has to be declared here: what these
	// tests move is the clock, and a role grant would only add a table this
	// package cannot reach without importing something that imports it back.
	store := &Store{db: db.DB, now: func() time.Time { return *at }}
	person, err := store.Ensure(t.Context(), "someone", "", true)
	if err != nil {
		t.Fatal(err)
	}
	return store, person.ID
}

func TestASessionStopsWorkingOnceItsLifetimeHasPassed(t *testing.T) {
	// The lifetime is not decoration. Group membership is read at sign-in and
	// never again, so this is the window in which somebody who moved out of a
	// team still holds what the team gave them.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		at := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
		store, person := atClock(t, db, &at)

		issued, err := store.StartSession(t.Context(), person, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.ResolveSession(t.Context(), issued.Token); err != nil {
			t.Fatalf("a session refused inside its lifetime: %v", err)
		}

		at = at.Add(time.Hour + time.Second)
		if _, _, err := store.ResolveSession(t.Context(), issued.Token); err == nil {
			t.Error("a session outlived its lifetime")
		}
	})
}

func TestClearingExpiredSessionsLeavesTheLiveOnesAlone(t *testing.T) {
	// Sessions are the one table here that grows with use rather than with
	// what is being tracked.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		at := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
		store, person := atClock(t, db, &at)

		brief, err := store.StartSession(t.Context(), person, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		lasting, err := store.StartSession(t.Context(), person, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}

		at = at.Add(2 * time.Hour)
		cleared, err := store.PurgeExpiredSessions(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if cleared != 1 {
			t.Errorf("cleared %d sessions, want 1", cleared)
		}
		if _, _, err := store.ResolveSession(t.Context(), lasting.Token); err != nil {
			t.Errorf("the live session was cleared too: %v", err)
		}
		if _, _, err := store.ResolveSession(t.Context(), brief.Token); err == nil {
			t.Error("the expired session still resolves")
		}
	})
}

func TestATokenStopsWorkingOnceItHasRunOut(t *testing.T) {
	// Expiry is the whole reason a personal token is safe to hand somebody:
	// a credential that never runs out is one nobody ever revokes.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		at := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
		store, person := atClock(t, db, &at)

		_, secret, err := store.NewToken(t.Context(), person, "scripting", nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.ResolveToken(t.Context(), secret); err != nil {
			t.Fatalf("a token refused inside its lifetime: %v", err)
		}

		at = at.Add(time.Hour + time.Second)
		if _, err := store.ResolveToken(t.Context(), secret); err == nil {
			t.Error("a token outlived its expiry")
		}
	})
}

func TestAProviderMayRefreshWhatAProviderGaveAndNotWhatSomebodySet(t *testing.T) {
	// An address has two sources and one column. The precedence is what
	// keeps the next sign-in from quietly undoing a correction somebody
	// made on purpose — written the other way round, an administrator
	// fixing a wrong address would watch it change back the moment its
	// owner signed in.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatal(err)
		}
		dbtest.Reset(t, db)
		store := NewStore(db.DB)
		person, err := store.Ensure(ctx, "ana", "Ana", false)
		if err != nil {
			t.Fatal(err)
		}

		// A provider fills in what nobody recorded.
		if err := store.SetEmail(ctx, person.ID, "ana@provider.example", FromProvider); err != nil {
			t.Fatal(err)
		}
		if got := reread(t, store, ctx, "ana"); got.Email != "ana@provider.example" || got.EmailSource != FromProvider {
			t.Fatalf("a provider filling an empty address left %q from=%v", got.Email, got.EmailSource)
		}

		// And may refresh its own.
		if err := store.SetEmail(ctx, person.ID, "ana@moved.example", FromProvider); err != nil {
			t.Fatal(err)
		}
		if got := reread(t, store, ctx, "ana"); got.Email != "ana@moved.example" {
			t.Errorf("a provider could not refresh what it gave: %q", got.Email)
		}

		// An administrator's overrides it and stops being a provider's.
		if err := store.SetEmail(ctx, person.ID, "ana@work.example", Recorded); err != nil {
			t.Fatal(err)
		}
		if got := reread(t, store, ctx, "ana"); got.Email != "ana@work.example" || got.EmailSource != Recorded {
			t.Fatalf("recording an address left %q from=%v", got.Email, got.EmailSource)
		}

		// After which a provider may not take it back.
		if err := store.SetEmail(ctx, person.ID, "ana@provider.example", FromProvider); err != nil {
			t.Fatal(err)
		}
		if got := reread(t, store, ctx, "ana"); got.Email != "ana@work.example" {
			t.Errorf("a sign-in undid what somebody recorded: %q", got.Email)
		}

		// A provider stating nothing is silent rather than asking for the
		// stored address to go.
		if err := store.SetEmail(ctx, person.ID, "", FromProvider); err != nil {
			t.Fatal(err)
		}
		if got := reread(t, store, ctx, "ana"); got.Email != "ana@work.example" {
			t.Errorf("a provider with no address cleared one: %q", got.Email)
		}

		// An administrator clearing it is how somebody comes off mail without
		// coming off the tool.
		if err := store.SetEmail(ctx, person.ID, "", Recorded); err != nil {
			t.Fatal(err)
		}
		if got := reread(t, store, ctx, "ana"); got.Email != "" {
			t.Errorf("an address could not be cleared: %q", got.Email)
		}

		// And a clearing is a decision, not an absence. Read as an absence, a
		// provider fills it straight back in and somebody taken off mail on
		// purpose is on it again by their next sign-in — which is the whole
		// reason the source has three states rather than two.
		if err := store.SetEmail(ctx, person.ID, "ana@provider.example", FromProvider); err != nil {
			t.Fatal(err)
		}
		if got := reread(t, store, ctx, "ana"); got.Email != "" {
			t.Errorf("a sign-in undid a clearing: %q", got.Email)
		}
	})
}

func reread(t *testing.T, store *Store, ctx context.Context, identity string) *Account {
	t.Helper()
	got, err := store.ByIdentity(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestAskingForWhatNobodyOwnsWithoutAskingForADigestIsRefused(t *testing.T) {
	// Every setting offered is one something reads. A person who asked for the
	// unowned list and not for a digest has set a value that changes nothing,
	// and a switch that changes nothing is worse than not offering it: they
	// believe they have asked for something.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatal(err)
		}
		dbtest.Reset(t, db)
		store := NewStore(db.DB)
		person, err := store.Ensure(ctx, "ana", "Ana", false)
		if err != nil {
			t.Fatal(err)
		}

		// Off until asked for.
		if got := reread(t, store, ctx, "ana"); got.Digest || got.DigestUnassigned {
			t.Fatalf("a new person is subscribed to something: %+v", got)
		}
		if err := store.SetDigest(ctx, person.ID, false, true); err == nil {
			t.Error("the unowned list was asked for without a digest to carry it")
		}
		if err := store.SetDigest(ctx, person.ID, true, true); err != nil {
			t.Fatal(err)
		}
		if got := reread(t, store, ctx, "ana"); !got.Digest || !got.DigestUnassigned {
			t.Errorf("what they asked for was not recorded: %+v", got)
		}
		// And turning the digest off takes the second with it, because the
		// second is part of the first.
		if err := store.SetDigest(ctx, person.ID, false, false); err != nil {
			t.Fatal(err)
		}
		if got := reread(t, store, ctx, "ana"); got.Digest || got.DigestUnassigned {
			t.Errorf("turning it off left something on: %+v", got)
		}
	})
}
