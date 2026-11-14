// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package saved_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/saved"
)

// A save whose commit is refused and taken again counts against the limit as
// it is when it is taken again: the limit is read inside the write.
func TestASaveTakenAgainReadsTheLimitAgain(t *testing.T) {
	var lower func()
	db, race := dbtest.Racing(t, func() { lower() })
	w := world.New(t, db)
	person, err := w.Access.Ensure(t.Context(), "someone@example.com", "Someone", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := saved.NewStore(db.DB)
	if _, err := store.SaveFilterPreparing(t.Context(), person.ID,
		"first", "component=linux", saved.Filter{}); err != nil {
		t.Fatal(err)
	}
	limitedTo(t, db, "2")
	lower = func() { limitedTo(t, db, "1") }

	race.Arm(1)
	_, err = store.SaveFilterPreparing(t.Context(), person.ID,
		"second", "component=busybox", saved.Filter{})
	if race.Unspent() != 0 {
		t.Fatal("the save committed nothing, so no attempt was taken again and this checks nothing")
	}
	if err == nil {
		t.Error("a save taken again after the limit was lowered to what the person keeps was kept")
	}
}

// A save taken again after a refused commit writes a row of its own. The row
// the first attempt inserted was rolled back, and its identifier can be
// somebody else's by the time the save is taken again.
func TestASaveTakenAgainCarriesNoIdentifierFromTheAttemptBefore(t *testing.T) {
	var between func()
	db, race := dbtest.Racing(t, func() { between() })
	w := world.New(t, db)
	person, err := w.Access.Ensure(t.Context(), "someone@example.com", "Someone", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := w.Access.Ensure(t.Context(), "other@example.com", "Other", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := saved.NewStore(db.DB)
	// Another person's save lands where the rolled-back row was.
	between = func() {
		if _, err := db.DB.NewInsert().Model(&saved.Filter{PersonID: other.ID, Name: "theirs",
			DisplayName: "Theirs", Query: "component=openssl", CreatedAt: time.Now().UTC()}).
			Exec(t.Context()); err != nil {
			t.Error(err)
		}
	}

	race.Arm(1)
	kept, err := store.SaveFilterPreparing(t.Context(), person.ID,
		"kernel", "component=linux", saved.Filter{})
	if race.Unspent() != 0 {
		t.Fatal("the save committed nothing, so no attempt was taken again and this checks nothing")
	}
	if err != nil {
		t.Fatalf("the save taken again answered %v", err)
	}
	mine, _, err := store.SavedFilters(t.Context(), person.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != 1 || mine[0].ID != kept.ID || mine[0].Query != "component=linux" {
		t.Errorf("the person keeps %+v, and the save answered %+v", mine, kept)
	}
	theirs, _, err := store.SavedFilters(t.Context(), other.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(theirs) != 1 || theirs[0].Name != "theirs" {
		t.Errorf("the other person keeps %+v, want their own filter", theirs)
	}
}

// A save taken again after a refused commit is dated by the attempt that
// wrote it, never by the one that rolled back.
func TestASaveTakenAgainIsDatedByTheAttemptThatWroteIt(t *testing.T) {
	db, race := dbtest.Racing(t, nil)
	w := world.New(t, db)
	person, err := w.Access.Ensure(t.Context(), "someone@example.com", "Someone", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	var calls int
	store := saved.NewStore(db.DB).WithClock(func() time.Time {
		calls++
		return first.Add(time.Duration(calls-1) * time.Hour)
	})

	race.Arm(1)
	kept, err := store.SaveFilterPreparing(t.Context(), person.ID,
		"kernel", "component=linux", saved.Filter{})
	if race.Unspent() != 0 {
		t.Fatal("the save committed nothing, so no attempt was taken again and this checks nothing")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !kept.CreatedAt.After(first) {
		t.Errorf("the save taken again is dated %v, the moment of the attempt that rolled back", kept.CreatedAt)
	}
}
