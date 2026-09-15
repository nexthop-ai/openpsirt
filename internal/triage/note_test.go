package triage_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestANoteIsWrittenWithoutRecordingAJudgment(t *testing.T) {
	// The whole of what a note is for. A comment hangs off a claim and the box
	// for one appears only where a claim already exists, so the first person
	// to say anything had to record a judgment in order to say it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.sits(t, access.Public)

		note, err := f.store.NoteOn(ctx, f.triager, f.product, f.issue,
			"Upstream says a patch lands next week; worth waiting rather than backporting.")
		if err != nil {
			t.Fatalf("writing a note before anybody decided anything was refused: %v", err)
		}
		if note.ID == 0 {
			t.Fatal("the note was not recorded")
		}
		// And nothing was decided by writing it.
		if standing, _ := f.store.Applying(ctx, f.at()); standing != nil {
			t.Error("writing a note recorded a judgment")
		}
	})
}

func TestANoteIsReadOnlyInTheProductItWasWrittenIn(t *testing.T) {
	// A note belongs to one product, like a rating. The same issue is often in
	// several products, and what one team knows about how they use a component
	// is not a statement about how another team uses it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.sits(t, access.Public)
		elsewhere := f.alongside(t, "other")

		if _, err := f.store.NoteOn(ctx, f.triager, f.product, f.issue,
			"We ship the vulnerable configuration."); err != nil {
			t.Fatal(err)
		}

		here, err := f.store.Notes(ctx, f.triager, f.product, f.issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(here) != 1 {
			t.Fatalf("the product it was written in holds %d notes, want 1", len(here))
		}
		// Read by somebody who holds the other product, where the issue also
		// sits: the thread there is empty rather than carrying this one.
		theirs := f.granted(t, "theirs-reader", elsewhere, access.PublicRead)
		there, err := f.store.Notes(ctx, theirs, elsewhere, f.issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(there) != 0 {
			t.Errorf("a note written in one product is readable in another: %d rows", len(there))
		}
	})
}

func TestANoteIsRefusedToSomebodyWhoHoldsNothingOnTheProduct(t *testing.T) {
	// Refused as a name nobody has used rather than as a denial: a note
	// carries what somebody wrote about an issue, so "you may not read this"
	// about a product somebody holds nothing on says the issue is there.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.sits(t, access.Public)
		if _, err := f.store.NoteOn(ctx, f.triager, f.product, f.issue,
			"Context for whoever decides."); err != nil {
			t.Fatal(err)
		}

		// A triager of another product, holding nothing here.
		elsewhere := f.alongside(t, "theirs")
		stranger := f.granted(t, "stranger", elsewhere, access.PublicTriage)

		if _, err := f.store.Notes(ctx, stranger, f.product, f.issue); !errors.Is(err, triage.ErrNoSuchNote) {
			t.Errorf("reading another product's notes answered %v, want the words a note that "+
				"is not there gets", err)
		}
		if _, err := f.store.NoteOn(ctx, stranger, f.product, f.issue,
			"Probing."); !errors.Is(err, triage.ErrNoSuchNote) {
			t.Errorf("writing into another product's notes answered %v, want the words a note "+
				"that is not there gets", err)
		}
	})
}

func TestReadingAnIssueHereDoesNotCarryWritingANoteHere(t *testing.T) {
	// Writing is arguing about work and reading is not. Somebody who may read
	// the product is told what the notes say and may not add to them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.sits(t, access.Public)
		if _, err := f.store.NoteOn(ctx, f.triager, f.product, f.issue,
			"Context for whoever decides."); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Notes(ctx, f.onlooker, f.product, f.issue); err != nil {
			t.Fatalf("somebody who may read the product cannot read its notes: %v", err)
		}
		if _, err := f.store.NoteOn(ctx, f.onlooker, f.product, f.issue,
			"Adding my own."); !errors.Is(err, access.ErrDenied) {
			t.Errorf("reading the product let somebody write a note: %v", err)
		}
	})
}

func TestAnUndisclosedPlaceMakesTheWholeThreadUndisclosed(t *testing.T) {
	// One undisclosed place among several makes the issue undisclosed for
	// anybody deciding what may be said, which is the rule the finding screen
	// already holds to. A note is one thread for the issue, so it cannot be
	// public for some of its places and private for others — and the safe
	// direction is the stricter one.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.build(t, f.product, "202411")
		f.finds(t, in, f.component(t, "libfoo", "1.2.3"), "place-one", access.Public)
		f.finds(t, in, f.component(t, "libbar", "4.5.6"), "place-two", access.Private)

		// The fixture's triager holds public triage only.
		if _, err := f.store.NoteOn(ctx, f.triager, f.product, f.issue,
			"Something about the embargoed half."); !errors.Is(err, access.ErrDenied) {
			t.Errorf("public triage wrote a note on an issue with an undisclosed place: %v", err)
		}
		keeper := f.granted(t, "keeper", f.product, access.PrivateTriage)
		if _, err := f.store.NoteOn(ctx, keeper, f.product, f.issue,
			"Something about the embargoed half."); err != nil {
			t.Fatalf("private triage could not write it either: %v", err)
		}
		if _, err := f.store.Notes(ctx, f.onlooker, f.product, f.issue); !errors.Is(err, triage.ErrNoSuchNote) {
			t.Errorf("a public reader was shown the thread on an issue with an undisclosed "+
				"place: %v", err)
		}
	})
}

func TestOnlyTheAuthorChangesANote(t *testing.T) {
	// An edit another person could make is not a correction, it is a forgery
	// with a timestamp.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.sits(t, access.Public)
		note, err := f.store.NoteOn(ctx, f.triager, f.product, f.issue, "First thought.")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.RewordNote(ctx, f.reviewer, note.ID, "Somebody else's words."); err == nil {
			t.Fatal("anybody holding triage here could rewrite somebody else's note")
		}
		if _, err := f.store.RewordNote(ctx, f.triager, note.ID, "Second thought."); err != nil {
			t.Fatalf("the author could not change their own note: %v", err)
		}
	})
}

func TestWhatANoteSaidBeforeIsKept(t *testing.T) {
	// A note goes public at disclosure with the rest of the record, and a
	// record whose earlier text is unrecoverable is readable rather than
	// checkable.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.sits(t, access.Public)
		note, err := f.store.NoteOn(ctx, f.triager, f.product, f.issue, "First thought.")
		if err != nil {
			t.Fatal(err)
		}
		for _, said := range []string{"Second thought.", "Third thought."} {
			if _, err := f.store.RewordNote(ctx, f.triager, note.ID, said); err != nil {
				t.Fatal(err)
			}
		}
		earlier, err := f.store.EarlierNote(ctx, f.triager, note.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(earlier) != 2 {
			t.Fatalf("two edits kept %d earlier versions", len(earlier))
		}
		if earlier[0].Body != "First thought." || earlier[1].Body != "Second thought." {
			t.Errorf("the versions kept are %q then %q, want them oldest first",
				earlier[0].Body, earlier[1].Body)
		}
		if earlier[0].Ordinal != 1 || earlier[1].Ordinal != 2 {
			t.Errorf("the versions are numbered %d and %d, want 1 and 2",
				earlier[0].Ordinal, earlier[1].Ordinal)
		}
		now, err := f.store.Notes(ctx, f.triager, f.product, f.issue)
		if err != nil {
			t.Fatal(err)
		}
		if now[0].Body != "Third thought." || now[0].EditedAt == nil {
			t.Errorf("the note now says %q, edited %v", now[0].Body, now[0].EditedAt)
		}
	})
}

// sits opens the fixture's issue at one place in one build of its product, so
// that there is something for a note to be about.
func (f *fixture) sits(t *testing.T, visibility access.Visibility) {
	t.Helper()
	in := f.build(t, f.product, "202411")
	f.finds(t, in, f.component(t, "libfoo", "1.2.3"), "place-of-libfoo", visibility)
}

// alongside declares a second product shipping the same issue, for the checks
// about what a note does not reach.
func (f *fixture) alongside(t *testing.T, name string) int64 {
	t.Helper()
	product, err := catalog.NewStore(f.db.DB).DeclareProduct(t.Context(), name, name)
	if err != nil {
		t.Fatalf("declare %s: %v", name, err)
	}
	in := f.build(t, product.ID, "202411")
	f.finds(t, in, f.component(t, "libfoo-"+name, "1.2.3"), "place-of-libfoo", access.Public)
	return product.ID
}

// granted is somebody holding one role on one product and nothing anywhere
// else.
func (f *fixture) granted(t *testing.T, identity string, productID int64,
	role access.Role) access.Subject {

	t.Helper()
	ctx := t.Context()
	rights := access.NewStore(f.db.DB)
	person, err := rights.Ensure(ctx, identity, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rights.GrantRole(ctx, person.ID, productID, role); err != nil {
		t.Fatal(err)
	}
	resolved, err := rights.Resolve(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestSomebodyBroughtOntoACaseReachesItsNotes(t *testing.T) {
	// A collaborator holds nothing on the product and is brought in on one
	// issue in it. The pair they were brought in on is the whole of what they
	// reach — and a note about that issue is inside the pair, so refusing it
	// would refuse them the one thing they were granted.
	//
	// The product's name has to resolve for them too. Refusing there would
	// refuse them the grant while telling them nothing they did not already
	// know: what they were told about names a product.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.sits(t, access.Private)
		rights := access.NewStore(f.db.DB)
		person, err := rights.Ensure(ctx, "collaborator", "Collaborator", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.AddToCase(ctx, f.product, f.issue, person.ID, f.proposer); err != nil {
			t.Fatal(err)
		}
		brought, err := rights.Resolve(ctx, "collaborator")
		if err != nil {
			t.Fatal(err)
		}
		if brought.Sees(f.product) {
			t.Fatal("the collaborator holds the product outright, so this tests nothing")
		}

		note, err := f.store.NoteOn(ctx, brought, f.product, f.issue,
			"We saw this in our own build last month.")
		if err != nil {
			t.Fatalf("somebody brought onto the case could not write a note on it: %v", err)
		}
		if _, err := f.store.Notes(ctx, brought, f.product, f.issue); err != nil {
			t.Fatalf("somebody brought onto the case could not read its notes: %v", err)
		}
		if _, err := f.store.RewordNote(ctx, brought, note.ID, "Corrected."); err != nil {
			t.Fatalf("somebody brought onto the case could not change their own note: %v", err)
		}

		// And nothing else of the product. Another issue there is one they
		// were not brought in on.
		other := f.anotherIssue(t, "CVE-2026-2")
		if _, err := f.store.Notes(ctx, brought, f.product, other); !errors.Is(err, triage.ErrNoSuchNote) {
			t.Errorf("the case grant reached an issue it does not name: %v", err)
		}
	})
}

// anotherIssue interns a second issue and opens it at a place in the fixture's
// product, so a case grant has something it does not cover to be refused on.
func (f *fixture) anotherIssue(t *testing.T, identifier string) int64 {
	t.Helper()
	ctx := t.Context()
	interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx, []finding.Named{
		{Identifier: identifier, Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := interned[identifier]
	in := f.build(t, f.product, "202505")
	row := &finding.Finding{
		TargetID: in.target, Kind: finding.Vulnerable, VulnerabilityID: id,
		Visibility: access.Public, ComponentID: f.component(t, "libbaz", "1.0"),
		PlaceIdentity: "place-of-libbaz",
		LastChangedAt: time.Now().Truncate(time.Microsecond),
		OpenedAt:      time.Now().Truncate(time.Microsecond), OpenedRunID: &in.run,
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}
