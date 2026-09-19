package access_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// asking is somebody who reads sonic at this visibility, which is what the
// picker and the mention resolver are answered for: what they hand back is a
// fact about work at that visibility, so the query carries the asker.
func asking(f *fixture, visibility access.Visibility) access.Subject {
	role := access.PublicRead
	if visibility == access.Private {
		role = access.PrivateRead
	}
	return access.NewPerson(0, "asking", false,
		map[int64][]access.Role{f.products["sonic"]: {role}}, 0)
}

// mentionable is who the picker offers for this visibility on sonic.
func mentionable(t *testing.T, f *fixture, visibility access.Visibility) []string {
	t.Helper()
	found, err := f.store.WhoCanRead(t.Context(), asking(f, visibility),
		f.products["sonic"], visibility, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(found))
	for _, one := range found {
		names = append(names, one.Identity)
	}
	return names
}

func has(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

// Only people who may already read it are offered.
//
// Administering the catalog is not reading its findings — that split is why
// the roles were separated — but the picker offered every administrator
// unconditionally. On an undisclosed finding the mention itself says a
// finding exists, so it told somebody holding nothing on the product that
// there is undisclosed work there, and the link they followed answered 404.
//
// Somebody who has left is refused at sign-in, so offering their name
// mentions a person who will never see it.
func TestThePickerOffersOnlyPeopleWhoMayRead(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		sonic := f.products["sonic"]

		// An administrator holding nothing on the product.
		if _, err := f.store.Ensure(ctx, "boss", "Boss", access.Stated(true), nil); err != nil {
			t.Fatal(err)
		}
		// A reader who is still here, and one who has left.
		reader, err := f.store.Ensure(ctx, "reader", "Reader", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		gone, err := f.store.Ensure(ctx, "gone", "Gone", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		// And somebody holding a bare capability, which grants no reading.
		approver, err := f.store.Ensure(ctx, "approver", "Approver", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for who, role := range map[int64]access.Role{
			reader.ID: access.PublicRead, gone.ID: access.PublicRead,
			approver.ID: access.Approver,
		} {
			if err := f.store.GrantRole(ctx, who, sonic, role); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.store.Deactivate(ctx, gone.ID); err != nil {
			t.Fatal(err)
		}

		public := mentionable(t, f, access.Public)
		if !has(public, "reader") {
			t.Errorf("somebody who may read it was not offered: %v", public)
		}
		if has(public, "boss") {
			t.Errorf("an administrator holding nothing here was offered: %v", public)
		}
		if has(public, "approver") {
			t.Errorf("a bare capability was treated as reading: %v", public)
		}
		if has(public, "gone") {
			t.Errorf("somebody who has left was offered: %v", public)
		}

		// And nobody at all at a visibility the reader does not reach.
		private := mentionable(t, f, access.Private)
		if len(private) != 0 {
			t.Errorf("nobody reads undisclosed work here, and %v were offered", private)
		}
	})
}

// A mention resolves the name it holds rather than paging the picker.
//
// It asked for the first hundred readers by identity and looked the name up
// in that page, so mentioning anybody sorting past position one hundred
// reached nobody — deterministically, growing with the deployment — and the
// author was told the name matched nobody at all.
func TestAMentionResolvesANamePastTheFirstPage(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		sonic := f.products["sonic"]

		for i := 0; i < 120; i++ {
			who, err := f.store.Ensure(ctx, strings.ToLower(
				"reader-"+string(rune('a'+i/26))+string(rune('a'+i%26))), "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.GrantRole(ctx, who.ID, sonic, access.PublicRead); err != nil {
				t.Fatal(err)
			}
		}
		last, err := f.store.Ensure(ctx, "zoe", "Zoe", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, last.ID, sonic, access.PublicRead); err != nil {
			t.Fatal(err)
		}

		found, err := f.store.ReadersNamed(ctx, asking(f, access.Public), sonic,
			access.Public, []string{"Zoe"})
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || found[0].ID != last.ID {
			t.Errorf("resolving a name sorting past the first page found %+v", found)
		}

		// A name nobody holds, and a name held by somebody who may not read
		// this, both come back absent and are not told apart.
		none, err := f.store.ReadersNamed(ctx, asking(f, access.Private), sonic,
			access.Private, []string{"Zoe", "nobody"})
		if err != nil {
			t.Fatal(err)
		}
		if len(none) != 0 {
			t.Errorf("somebody who may not read undisclosed work resolved: %+v", none)
		}
	})
}

// The gate is on the query, not on the two handlers that happen to call it.
//
// Both of them do authorize before a name is resolved, and the ordering is
// right. Written out at each of them, the gate leaves a third endpoint over
// this query answering for everybody. This asks the store directly, with a
// subject that may not read what is being asked about.
func TestAskingWhoReadsSomethingIsAskedWithASubject(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		sonic := f.products["sonic"]
		who, err := f.store.Ensure(ctx, "hidden-reader", "Hidden Reader", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.GrantRole(ctx, who.ID, sonic, access.PrivateRead); err != nil {
			t.Fatal(err)
		}
		// Somebody who reads what is disclosed here and nothing more, asking
		// who reads what is not.
		public := access.NewPerson(0, "asking", false,
			map[int64][]access.Role{sonic: {access.PublicRead}}, 0)

		offered, err := f.store.WhoCanRead(ctx, public, sonic, access.Private, "", 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(offered) != 0 {
			t.Errorf("the picker answered who reads undisclosed work to somebody who "+
				"may not: %+v", offered)
		}
		named, err := f.store.ReadersNamed(ctx, public, sonic, access.Private,
			[]string{"hidden-reader"})
		if err != nil {
			t.Fatal(err)
		}
		if len(named) != 0 {
			t.Errorf("resolving a name against undisclosed work answered somebody who "+
				"may not read it: %+v", named)
		}
		// And it still answers the person who may, so this is a gate rather
		// than a query that returns nothing.
		private := access.NewPerson(0, "asking", false,
			map[int64][]access.Role{sonic: {access.PrivateRead}}, 0)
		stands, err := f.store.ReadersNamed(ctx, private, sonic, access.Private,
			[]string{"hidden-reader"})
		if err != nil {
			t.Fatal(err)
		}
		if len(stands) != 1 {
			t.Errorf("somebody who may read undisclosed work resolved %+v", stands)
		}
	})
}

// TestASearchTermIsNotAPatternLanguage pins what a wildcard in a search box
// does, on the picker where it matters most.
//
// Four LIKE predicates carried no ESCAPE while eight beside them did, so a "%"
// or a "_" was a wildcard in four places and a literal in eight. This is the
// picker that decides who may be named on an embargoed case: a term of "%"
// answered with every person the deployment could offer, in one request.
//
// Every engine, because SQLite has no default escape character and the other
// three disagree about a backslash — which is why the escape character here is
// "#" and why the clause is always stated.
func TestASearchTermIsNotAPatternLanguage(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		product := f.products["sonic"]

		// Two identities differing only where a wildcard would not care.
		for _, identity := range []string{"ana_ruiz", "anaxruiz"} {
			person, err := f.store.Ensure(ctx, identity, "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.Claim(ctx, person.ID, identity); err != nil {
				t.Fatal(err)
			}
			if err := f.store.GrantRole(ctx, person.ID, product, access.PrivateRead); err != nil {
				t.Fatal(err)
			}
		}

		asker := asking(f, access.Private)

		// The underscore is a character, not "any character".
		found, err := f.store.WhoCanRead(ctx, asker, product, access.Private, "ana_", 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || found[0].Identity != "ana_ruiz" {
			t.Errorf("searching %q found %v, want the one literal match",
				"ana_", identities(found))
		}

		// And a bare wildcard is a name nobody has, rather than everybody.
		everyone, err := f.store.WhoCanRead(ctx, asker, product, access.Private, "%", 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(everyone) != 0 {
			t.Errorf("a term of %q answered with %v — the whole embargo picker in "+
				"one request", "%", identities(everyone))
		}
	})
}

func identities(found []access.Mentionable) []string {
	out := make([]string, 0, len(found))
	for _, one := range found {
		out = append(out, one.Identity)
	}
	return out
}
