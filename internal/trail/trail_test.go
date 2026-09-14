package trail_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// each is one migrated database per engine, with a person to record changes
// against: a change nobody made is a change nothing records, which is the
// state this store exists to end.
func each(t *testing.T, fn func(t *testing.T, s *trail.Store, by access.Subject)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		person, err := access.NewStore(db.DB).Ensure(ctx, "them@example.com", "Them", true)
		if err != nil {
			t.Fatal(err)
		}
		fn(t, trail.NewStore(db.DB),
			access.NewPerson(person.ID, "them@example.com", true, nil, 0))
	})
}

func TestTheTrailRecordsAndPagesOnEveryEngine(t *testing.T) {
	// This store had no test of its own at all — its only coverage was
	// through handlers, which run on two engines, so neither its writes
	// nor the ordering its reader depends on had ever executed on MySQL or
	// MariaDB.
	each(t, func(t *testing.T, s *trail.Store, by access.Subject) {
		ctx := t.Context()

		// Absent before means nobody had set it; absent after means it was
		// cleared. The two are different acts and a blank cannot tell them
		// apart, so both have to survive a round trip through four engines.
		for _, one := range []struct {
			kind        trail.Kind
			name        string
			was, became *string
		}{
			{trail.Setting, "triage-floor", nil, trail.Said("high", true)},
			{trail.Setting, "triage-floor", trail.Said("high", true), trail.Said("medium", true)},
			{trail.Support, "sonic/master", trail.Said("2030-01-01", true), trail.Said("", false)},
			{trail.Role, "them@example.com", nil, trail.Said("private-triage", true)},
		} {
			if err := s.Record(ctx, by, one.kind, one.name, one.was, one.became); err != nil {
				t.Fatal(err)
			}
		}

		all, total, err := s.Changes(ctx, "", 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 4 || len(all) != 4 {
			t.Fatalf("the trail holds %d changes and returned %d, want four", total, len(all))
		}
		// Newest first, and the tie broken by identifier: four changes
		// written inside one microsecond otherwise come back in whatever
		// order an engine happens to hold them, which makes a paged reader
		// skip and repeat rows.
		for i := 1; i < len(all); i++ {
			if all[i-1].ID < all[i].ID {
				t.Fatalf("the trail is not newest first: %d before %d",
					all[i-1].ID, all[i].ID)
			}
		}
		// The cleared one kept the difference between "nobody had set it" and
		// "it was cleared".
		var cleared *trail.Change
		for i := range all {
			if all[i].Kind == trail.Support {
				cleared = &all[i]
			}
		}
		if cleared == nil || cleared.Was == nil || cleared.Became != nil {
			t.Errorf("a cleared value came back as %+v, want a before and no after", cleared)
		}

		// Filtered by kind, and paged.
		settings, count, err := s.Changes(ctx, trail.Setting, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		if count != 2 || len(settings) != 1 {
			t.Errorf("one page of the settings changes is %d of %d, want one of two",
				len(settings), count)
		}
		second, _, err := s.Changes(ctx, trail.Setting, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(second) != 1 || second[0].ID == settings[0].ID {
			t.Errorf("the second page repeats the first: %+v then %+v", settings, second)
		}

		// A change nobody made is refused rather than recorded against
		// nobody, which is the state this exists to end.
		if err := s.Record(ctx, access.Subject{}, trail.Setting, "triage-floor",
			nil, trail.Said("low", true)); err == nil {
			t.Error("a change with nobody behind it was recorded")
		}
	})
}
