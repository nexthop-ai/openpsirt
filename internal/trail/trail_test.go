// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package trail_test

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// each is the seeded world per engine, with somebody to record changes
// against: a change nobody made is a change nothing records, which is the
// state this store exists to end.
func each(t *testing.T, fn func(t *testing.T, s *trail.Store, by access.Subject)) {
	t.Helper()
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		admin := w.DeclarePerson("admin@example.com", "Alex Admin", true)
		fn(t, trail.NewStore(w.DB.DB),
			access.NewPerson(admin.ID, admin.Identity, true, nil, 0))
	})
}

func TestTheTrailRecordsAndPagesOnEveryEngine(t *testing.T) {
	// The store's writes and the ordering its reader depends on run here on
	// all four engines; the handlers above it run on two.
	each(t, func(t *testing.T, s *trail.Store, by access.Subject) {
		ctx := t.Context()
		// Every row shares one instant, so the order below is the tie-break
		// alone: changes written inside one microsecond — one request
		// granting several roles — are the case a paged reader meets.
		at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
		s.SetClock(func() time.Time { return at })

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

		all, total, err := s.Changes(ctx, by, "", trail.Over{}, 100, 0)
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
			if all[i-1].ID <= all[i].ID {
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
		settings, count, err := s.Changes(ctx, by, trail.Setting, trail.Over{}, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		if count != 2 || len(settings) != 1 {
			t.Errorf("one page of the settings changes is %d of %d, want one of two",
				len(settings), count)
		}
		second, _, err := s.Changes(ctx, by, trail.Setting, trail.Over{}, 1, 1)
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

func TestOnePersonsHistoryIsNotAnothersThatMatchesItUnderLike(t *testing.T) {
	// About finds the rows named for somebody alone and the rows naming them
	// beside a product — "a_b@example.com on sonic" — so the second half is a
	// prefix match. An underscore is a single-character wildcard to LIKE, so
	// without the escaping "a_b@example.com" also matches "axb@example.com"
	// and one person's administrative history is reported as another's.
	//
	// The escaping is one statement in this package and About's only other
	// caller is a handler, so this is what reaches either. The four engines
	// are the point as well: the ESCAPE clause parses differently on each, and
	// one of them refuses a backslash outright, which is why the escape
	// character is a hash.
	each(t, func(t *testing.T, s *trail.Store, by access.Subject) {
		ctx := t.Context()
		for _, about := range []string{
			"a_b@example.com on sonic",
			"axb@example.com on sonic",
			"a_b@example.com",
			// A percent sign is the other wildcard, and the hash is the
			// escape character itself.
			"a%b@example.com on sonic",
			"a#b@example.com on sonic",
		} {
			if err := s.Record(ctx, by, trail.Role, about,
				nil, trail.Said("private-triage", true)); err != nil {
				t.Fatalf("record %q: %v", about, err)
			}
		}

		for _, want := range []struct {
			name  string
			total int
		}{
			// The row named for them alone, and the row naming them beside a
			// product. Never the row that only matches because an underscore
			// stood in for a character.
			{"a_b@example.com", 2},
			{"axb@example.com", 1},
			{"a%b@example.com", 1},
			{"a#b@example.com", 1},
		} {
			got, total, err := s.About(ctx, by, trail.Role, want.name, 100, 0)
			if err != nil {
				t.Fatalf("read what changed about %q: %v", want.name, err)
			}
			if total != want.total || len(got) != want.total {
				t.Errorf("%q has %d change(s) and %d were read, want %d",
					want.name, total, len(got), want.total)
			}
			for _, change := range got {
				if change.Name != want.name && change.Name != want.name+" on sonic" {
					t.Errorf("reading about %q returned a change about %q",
						want.name, change.Name)
				}
			}
		}
	})
}

// TestTheTrailRefusesAReaderWhoDoesNotAdminister pins that the store, rather
// than a handler, refuses a reader who does not administer.
//
// A row names who was brought into which case, and an undisclosed case is
// among them, so this is a question about who may read a query rather than a
// shape a handler happens to guard (REQ-42 and REQ-43). Refused rather than
// answered empty: a reader who may not ask is told so, instead of being shown
// a deployment where nobody has ever changed anything.
func TestTheTrailRefusesAReaderWhoDoesNotAdminister(t *testing.T) {
	each(t, func(t *testing.T, s *trail.Store, by access.Subject) {
		ctx := t.Context()
		if err := s.Record(ctx, by, trail.Case,
			"sonic · CVE-2026-0001 · them@example.com", nil,
			trail.Said("a collaborator", true)); err != nil {
			t.Fatal(err)
		}

		// Somebody real, holding everything except administration.
		reader := access.NewPerson(by.ID+1, "reader@example.com", false, nil, 0)
		if _, _, err := s.Changes(ctx, reader, "", trail.Over{}, 100, 0); !errors.Is(err, access.ErrDenied) {
			t.Errorf("listing the trail as a non-administrator answered %v, want a refusal", err)
		}
		if _, _, err := s.About(ctx, reader, trail.Case, "sonic", 100, 0); !errors.Is(err, access.ErrDenied) {
			t.Errorf("reading about one subject as a non-administrator answered %v, want a refusal", err)
		}

		// The deployment itself still reads it: a background pass answers
		// nobody, and refusing it would be a refusal that reads as a bug.
		if _, _, err := s.Changes(ctx, access.Everything("reporting on the tool"),
			"", trail.Over{}, 100, 0); err != nil {
			t.Errorf("the deployment could not read its own trail: %v", err)
		}
	})
}

// TestARecordCannotOverflowItsOwnColumn pins the backstop under every caller.
//
// The rows here are composed by whoever is recording — a collaborator is
// a product, an issue and a person — and the column is sized for three names
// and their separators. Every caller composes from stored values, so this
// never fires; it is here because "every caller does the right thing" is not a
// property anything checks, and the failure it would otherwise take is the act
// refused on the three engines that will not hold an over-long value.
func TestARecordCannotOverflowItsOwnColumn(t *testing.T) {
	each(t, func(t *testing.T, s *trail.Store, by access.Subject) {
		ctx := t.Context()

		// Past the column, and multi-byte, so a bound counting bytes would cut
		// a rune in half and store something that is not text.
		long := strings.Repeat("é", trail.NameLimit+200)
		if err := s.Record(ctx, by, trail.Setting, long, nil, trail.Said("moved", true)); err != nil {
			t.Fatalf("a long name was refused rather than bounded: %v", err)
		}

		changes, _, err := s.Changes(ctx, by, trail.Setting, trail.Over{}, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(changes) == 0 {
			t.Fatal("nothing was recorded")
		}
		kept := changes[0].Name
		if n := utf8.RuneCountInString(kept); n > trail.NameLimit {
			t.Errorf("the record kept %d runes, past the %d the column holds", n, trail.NameLimit)
		}
		if !utf8.ValidString(kept) {
			t.Error("the record was cut mid-rune, so what is stored is not text")
		}
		if !strings.HasPrefix(long, kept) {
			t.Error("what was kept is not the head of what was asked for")
		}
	})
}

// TestAMaximalCaseFitsTheColumn pins the width against the widest thing
// recorded.
//
// The column is sized for three maximal names and their separators. The
// fixtures compose nothing near maximal, so a composition gaining a part or a
// name widening overflows the column only here — and with the record inside
// the act, an overflow takes down the act.
func TestAMaximalCaseFitsTheColumn(t *testing.T) {
	each(t, func(t *testing.T, s *trail.Store, by access.Subject) {
		ctx := t.Context()

		// A product, an issue and a person, each as wide as a name column
		// holds, with the separators the recorder puts between them.
		wide := strings.Repeat("W", database.NameWidth)
		about := wide + " · " + wide + " · " + wide
		if utf8.RuneCountInString(about) > trail.NameLimit {
			t.Fatalf("the widest thing recorded is %d runes and the column holds %d",
				utf8.RuneCountInString(about), trail.NameLimit)
		}

		if err := s.Record(ctx, by, trail.Case, about,
			nil, trail.Said("a collaborator", true)); err != nil {
			t.Fatalf("a maximal case could not be recorded: %v", err)
		}
		changes, _, err := s.Changes(ctx, by, trail.Case, trail.Over{}, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(changes) == 0 || changes[0].Name != about {
			t.Error("a maximal case did not come back as it was written")
		}
	})
}

// Configuration names administrators with no person behind the change, and
// the trail records each one it names and each one it stops naming against
// configuration. A start that changes nothing records nothing.
func TestConfigurationsAdministratorsAreRecordedAgainstConfiguration(t *testing.T) {
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		ctx := t.Context()
		admin := w.DeclarePerson("admin@example.com", "Alex Admin", true)
		reader := access.NewPerson(admin.ID, admin.Identity, true, nil, 0)
		s := trail.NewStore(w.DB.DB)
		accounts := func() []trail.Change {
			t.Helper()
			changes, _, err := s.Changes(ctx, reader, trail.Account, trail.Over{}, 100, 0)
			if err != nil {
				t.Fatal(err)
			}
			return changes
		}

		if _, err := trail.NameAdministrators(ctx, w.DB.DB, []string{"operator"}); err != nil {
			t.Fatal(err)
		}
		named := accounts()
		if len(named) != 1 {
			t.Fatalf("naming one administrator left %d rows, want 1", len(named))
		}
		if one := named[0]; one.Actor != trail.ByConfiguration || one.By != nil ||
			one.Name != "operator" || one.Was != nil ||
			one.Became == nil || *one.Became != trail.NamedInConfiguration {
			t.Errorf("naming an administrator was recorded as %+v", one)
		}

		// Restarted naming the same people.
		if _, err := trail.NameAdministrators(ctx, w.DB.DB, []string{"operator"}); err != nil {
			t.Fatal(err)
		}
		if again := accounts(); len(again) != 1 {
			t.Errorf("a start naming the same people left %d rows, want the one", len(again))
		}

		unnamed, err := trail.NameAdministrators(ctx, w.DB.DB, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(unnamed) != 1 || unnamed[0] != "operator" {
			t.Errorf("the names no longer in configuration came back as %v", unnamed)
		}
		removed := accounts()
		if len(removed) != 2 {
			t.Fatalf("removing the name left %d rows, want 2", len(removed))
		}
		if one := removed[0]; one.Actor != trail.ByConfiguration || one.By != nil ||
			one.Was == nil || *one.Was != trail.NamedInConfiguration ||
			one.Became == nil || *one.Became != trail.UnnamedByConfiguration {
			t.Errorf("removing an administrator's name was recorded as %+v", one)
		}

		// And a person's change is still a person's.
		if err := s.Record(ctx, reader, trail.Setting, "triage-floor", nil, trail.Said("high", true)); err != nil {
			t.Fatal(err)
		}
		changes, _, err := s.Changes(ctx, reader, trail.Setting, trail.Over{}, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(changes) != 1 || changes[0].Actor != trail.ByPerson || changes[0].Person() != admin.ID {
			t.Errorf("a person's change was recorded as %+v", changes)
		}
	})
}

// TestTheTrailPeriodIsHalfOpen pins the boundaries of a period.
//
// An audit asks what changed in the year a certificate covers, and the next
// year's audit asks the same of the year after. A change stamped exactly at
// the boundary belongs to one of the two and never both, so the start is
// included and the end is not.
func TestTheTrailPeriodIsHalfOpen(t *testing.T) {
	each(t, func(t *testing.T, s *trail.Store, by access.Subject) {
		ctx := t.Context()
		boundary := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for _, one := range []struct {
			name string
			at   time.Time
		}{
			{"before", boundary.Add(-time.Second)},
			{"at", boundary},
			{"after", boundary.Add(time.Second)},
		} {
			s.SetClock(func() time.Time { return one.at })
			if err := s.Record(ctx, by, trail.Setting, one.name, nil, trail.Said("x", true)); err != nil {
				t.Fatal(err)
			}
		}

		for _, want := range []struct {
			over  trail.Over
			names []string
		}{
			{trail.Over{Since: boundary}, []string{"after", "at"}},
			{trail.Over{Until: boundary}, []string{"before"}},
			{trail.Over{Since: boundary, Until: boundary.Add(time.Second)}, []string{"at"}},
		} {
			got, total, err := s.Changes(ctx, by, "", want.over, 100, 0)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, c := range got {
				names = append(names, c.Name)
			}
			if strings.Join(names, ",") != strings.Join(want.names, ",") || total != len(want.names) {
				t.Errorf("from %v to %v answered %v (total %d), want %v",
					want.over.Since, want.over.Until, names, total, want.names)
			}
		}
	})
}

// Each mapping configuration adds or stops stating is recorded against
// configuration, and so is where roles come from when the first mapping
// arrives and when the last one goes. A start stating what the last one stated
// records nothing.
func TestConfigurationsGroupMappingsAreRecordedAgainstConfiguration(t *testing.T) {
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		ctx := t.Context()
		admin := w.DeclarePerson("admin@example.com", "Alex Admin", true)
		reader := access.NewPerson(admin.ID, admin.Identity, true, nil, 0)
		s := trail.NewStore(w.DB.DB)
		of := func(kind trail.Kind) []trail.Change {
			t.Helper()
			changes, _, err := s.Changes(ctx, reader, kind, trail.Over{}, 100, 0)
			if err != nil {
				t.Fatal(err)
			}
			return changes
		}
		leads := access.Mapping{Group: "leads", Grants: string(access.Administers)}
		// A role assigned under People, which the first mapping sets aside and
		// the last one's removal restores.
		product := w.DeclareProduct("assigned", "Assigned")
		holder := w.DeclarePerson("holder@example.com", "Holder", false)
		rights := access.NewStore(w.DB.DB)
		if err := rights.GrantRole(ctx, holder.ID, product.ID, access.PublicRead); err != nil {
			t.Fatal(err)
		}
		active := func() bool {
			t.Helper()
			grants, err := rights.Grants(ctx, holder.ID)
			if err != nil || len(grants) != 1 {
				t.Fatalf("the assigned role read back as %+v (%v)", grants, err)
			}
			return grants[0].Active
		}

		// Mappings granting no administration, with nobody named, are refused,
		// and the refusal changes nothing.
		if _, _, err := trail.MapGroups(ctx, w.DB.DB, []access.Mapping{
			{Group: "readers", Grants: string(access.PublicRead)},
		}); !errors.Is(err, access.ErrNobodyAdministers) {
			t.Errorf("mappings nobody could administer under answered %v", err)
		}
		if roles := of(trail.Role); len(roles) != 0 || !active() {
			t.Errorf("a refused start recorded %+v, or set the assigned role aside", roles)
		}

		mapped, mode, err := trail.MapGroups(ctx, w.DB.DB, []access.Mapping{leads})
		if err != nil {
			t.Fatal(err)
		}
		if mode != access.GroupBound || len(mapped.Added) != 1 {
			t.Errorf("the first mapping answered %s and %+v", mode, mapped)
		}
		roles := of(trail.Role)
		if len(roles) != 1 {
			t.Fatalf("one mapping left %d rows, want 1", len(roles))
		}
		if one := roles[0]; one.Actor != trail.ByConfiguration || one.By != nil ||
			one.Name != "leads over this deployment" || one.Was != nil ||
			one.Became == nil || *one.Became != "admin" {
			t.Errorf("a mapping was recorded as %+v", one)
		}
		if active() {
			t.Error("the first mapping left a role assigned under People in force")
		}
		settings := of(trail.Setting)
		if len(settings) != 1 || settings[0].Actor != trail.ByConfiguration ||
			settings[0].Became == nil || *settings[0].Became != string(access.GroupBound) {
			t.Errorf("the switch to group-bound was recorded as %+v", settings)
		}

		if _, _, err := trail.MapGroups(ctx, w.DB.DB, []access.Mapping{leads}); err != nil {
			t.Fatal(err)
		}
		if len(of(trail.Role)) != 1 || len(of(trail.Setting)) != 1 {
			t.Error("a start stating the same mappings recorded something")
		}

		if _, mode, err = trail.MapGroups(ctx, w.DB.DB, nil); err != nil {
			t.Fatal(err)
		}
		if mode != access.Direct {
			t.Errorf("no mappings answered %s", mode)
		}
		if !active() {
			t.Error("removing the last mapping did not restore the role assigned under People")
		}
		roles = of(trail.Role)
		if len(roles) != 2 || roles[0].Was == nil || *roles[0].Was != "admin" || roles[0].Became != nil {
			t.Errorf("withdrawing the mapping was recorded as %+v", roles)
		}
		if settings = of(trail.Setting); len(settings) != 2 ||
			*settings[0].Became != string(access.Direct) {
			t.Errorf("the switch back to direct was recorded as %+v", settings)
		}
	})
}
