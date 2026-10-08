// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// atClock is a store whose sense of now a test moves, because a session
// expires by time passing rather than by being born expired — a lifetime of
// zero or less is taken as "unstated" and becomes the default, so there is no
// way to ask for one that has already run out.
func atClock(t *testing.T, db *database.DB, at *time.Time) (*Store, int64) {
	t.Helper()
	// An administrator, so that no product has to be declared here: what these
	// tests move is the clock, and a role grant would only add a table this
	// package cannot reach without importing something that imports it back.
	store := &Store{db: db.DB, now: func() time.Time { return *at }}
	person, err := store.Ensure(t.Context(), "someone", "Someone", Stated(true), nil)
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

		_, secret, err := store.NewToken(t.Context(), person, "scripting", nil, nil, time.Hour, 0)
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
		store := NewStore(db.DB)
		person, err := store.Ensure(ctx, "ana", "Ana", nil, nil)
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
		store := NewStore(db.DB)
		person, err := store.Ensure(ctx, "ana", "Ana", nil, nil)
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

// TestARefusedInsertIsForgivenOnlyAsADuplicate pins the narrowing the public
// API cannot show.
//
// Only a uniqueness violation means "somebody got there first". A failure
// caused by something else, with a row there just the same, is not a grant the
// caller may believe in.
//
// In this package because the guard takes the store's own error: through a
// store method a foreign-key failure and a duplicate both end in an error, and
// the difference does not show. Every engine, because what each calls "that
// already exists" is a different code in a different type, and the duplicate
// here is a real one from whichever engine is running.
func TestARefusedInsertIsForgivenOnlyAsADuplicate(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		store := NewStore(db.DB)

		person, err := store.Ensure(ctx, "ana", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		row := func() *Identity {
			return &Identity{PersonID: person.ID, Username: "ana", CreatedAt: store.now()}
		}
		present := func(context.Context) (bool, error) { return true, nil }

		wrote, err := store.insertOnce(ctx, "claim", row(), present)
		if err != nil || !wrote {
			t.Fatalf("the first insert answered %v, %v", wrote, err)
		}

		// A duplicate, with the row there: the state the caller asked for
		// holds, and nothing was written.
		wrote, err = store.insertOnce(ctx, "claim", row(), present)
		if err != nil {
			t.Errorf("a duplicate with the row there was refused: %v", err)
		}
		if wrote {
			t.Error("a duplicate was reported as a row written")
		}

		// Anything else, with the row there just the same. Forgiving this is
		// reporting a grant the failure may well have prevented.
		gone, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := store.insertOnce(gone, "claim", row(), present); err == nil {
			t.Fatal("a failure that was not a duplicate was reported as success")
		} else if !errors.Is(err, context.Canceled) {
			t.Errorf("the refusal loses what actually failed: %v", err)
		}

		// And a duplicate whose row does not satisfy the caller's predicate
		// says what happened rather than handing back the constraint message.
		absent := func(context.Context) (bool, error) { return false, nil }
		_, err = store.insertOnce(ctx, "claim", row(), absent)
		if err == nil {
			t.Fatal("a duplicate whose row grants nothing was reported as success")
		}
		if strings.Contains(err.Error(), "constraint") ||
			strings.Contains(err.Error(), "Duplicate") {
			t.Errorf("the engine's constraint message reached the caller: %v", err)
		}
	})
}

// A duplicate refused inside a transaction leaves the transaction usable.
//
// On PostgreSQL a refused statement aborts the transaction around it, so the
// read asking whether the state holds fails, and so does everything written
// after it. An administrative act granting what somebody already holds runs
// inside one, and is documented as succeeding and changing nothing.
func TestADuplicateInsideATransactionLeavesItUsable(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		person, err := NewStore(db.DB).Ensure(ctx, "ana", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			err := database.InTransaction(ctx, db.DB, func(ctx context.Context, tx bun.Tx) error {
				store := NewStore(tx)
				if err := store.GrantEstateRole(ctx, person.ID, PublicRead); err != nil {
					return err
				}
				// Something after it, which a poisoned transaction refuses.
				_, err := store.ByIdentity(ctx, "ana")
				return err
			})
			if err != nil {
				t.Fatalf("granting what is already held, inside a transaction: %v", err)
			}
		}
	})
}

// A conditional write that matched nothing lost a race, and says so rather
// than reporting a move it did not make: the caller records the move from the
// value it read, so success here would put a change nobody made in the trail.
func TestAMoveThatLostARaceIsTakenAgain(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		at := time.Now()
		store, id := atClock(t, db, &at)
		// Read before another writer withdrew administration and granted
		// auditing, so both values it holds are stale.
		stale, err := store.byID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Ensure(ctx, "someone", "", Stated(false), Stated(true)); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			what          string
			admin, audits *bool
		}{
			{"administration", Stated(false), nil},
			{"auditing", nil, Stated(true)},
		} {
			copied := *stale
			if err := store.move(ctx, &copied, c.admin, c.audits); !errors.Is(err, database.ErrGoAgain) {
				t.Errorf("a move of %s that matched nothing answered %v", c.what, err)
			}
		}
	})
}

// A rename conditioned on a name somebody else has since replaced matched
// nothing, writes nothing and says so, and one conditioned on the name held
// moves it, from no name as well as from one.
func TestARenameThatLostARaceIsTakenAgain(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		at := time.Now()
		store, id := atClock(t, db, &at)
		named := func() string {
			t.Helper()
			person, err := store.byID(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			return person.DisplayName
		}

		if err := store.SetDisplayName(ctx, id, "Someone", "Ada"); err != nil {
			t.Fatalf("renaming somebody: %v", err)
		}
		if err := store.SetDisplayName(ctx, id, "Someone", "Grace"); !errors.Is(err, database.ErrGoAgain) {
			t.Errorf("a rename from a name already replaced answered %v", err)
		}
		if got := named(); got != "Ada" {
			t.Errorf("a rename that lost its race left the name %q", got)
		}
		if err := store.SetDisplayName(ctx, id, "Ada", ""); err != nil {
			t.Fatalf("clearing the name: %v", err)
		}
		if got := named(); got != "" {
			t.Errorf("a cleared name reads %q", got)
		}
		if err := store.SetDisplayName(ctx, id, "", "Ada"); err != nil {
			t.Errorf("naming somebody unnamed: %v", err)
		}
	})
}

// What Restate answers as before is the value its own write was made against.
// Another writer that got there first leaves before and after equal, so the
// caller records no move; a caller reading before for itself could have read
// the value the other writer replaced.
func TestRestatingSaysWhatTheWriteMovedFrom(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		at := time.Now()
		store, _ := atClock(t, db, &at)

		// Another administrator withdrew it first.
		if _, err := store.Ensure(ctx, "someone", "", Stated(false), nil); err != nil {
			t.Fatal(err)
		}
		before, after, err := store.Restate(ctx, "someone", "", Stated(false), nil)
		if err != nil {
			t.Fatal(err)
		}
		if before.IsAdmin || after.IsAdmin {
			t.Errorf("a withdrawal somebody else made read as %v then %v", before.IsAdmin, after.IsAdmin)
		}

		before, after, err = store.Restate(ctx, "someone", "", Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		if before.IsAdmin || !after.IsAdmin {
			t.Errorf("a grant this write made read as %v then %v", before.IsAdmin, after.IsAdmin)
		}

		before, after, err = store.Restate(ctx, "somebody-new", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if before != nil || after == nil {
			t.Errorf("somebody newly recorded read as %v then %v", before, after)
		}
	})
}
