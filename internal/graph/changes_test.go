package graph_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Which names one upload moved, rather than how many. The counts on a receipt
// and this listing are one comparison read two ways, so what these pin is that
// the two cannot disagree — and that what a reader sees first is what a build
// going wrong looks like.

// changes asks for one scan's whole listing.
func changes(t *testing.T, f *fixture, scanID int64) []graph.Change {
	t.Helper()
	listed, total, err := f.store.Changes(t.Context(), everyone(f), f.targetID, scanID, "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != len(listed) {
		t.Errorf("the whole listing is %d rows and the total says %d", len(listed), total)
	}
	return listed
}

// spelled is a listing as words, for comparing a whole answer at once.
func spelled(listed []graph.Change) []string {
	out := make([]string, 0, len(listed))
	for _, change := range listed {
		out = append(out, string(change.Kind)+" "+change.Name+
			" ["+strings.Join(change.Before, " ")+"] -> ["+strings.Join(change.After, " ")+"]")
	}
	return out
}

func TestTheListingNamesWhatArrivedWentAndMoved(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())

		// curl goes, openssl moves version, zlib arrives.
		bumped := at("openssl", "3.0.12")
		next := graph.Snapshot{
			Root: root, Components: []graph.Described{bumped, zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: bumped},
				{Parent: root, Child: zlib},
			},
		}
		got := spelled(changes(t, f, applied(t, f, next)))
		want := []string{
			"removed curl [8.4.0] -> []",
			"added zlib [] -> [1.3]",
			"changed openssl [3.0.11] -> [3.0.12]",
		}
		if strings.Join(got, "; ") != strings.Join(want, "; ") {
			t.Errorf("the listing reads\n%v\nwant\n%v", got, want)
		}
	})
}

func TestRemovalsAreReadFirst(t *testing.T) {
	// A build that stopped describing a dependency looks exactly like one
	// that stopped shipping it, so it is the row somebody opens this to find.
	// Ordered by name alone it would sit wherever the alphabet put it.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())

		// The name that goes sorts last of the three, so an ordering that
		// forgot the kind would put it at the bottom.
		arriving := at("aalib", "1.4")
		next := graph.Snapshot{
			Root: root, Components: []graph.Described{arriving, openssl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: arriving},
				{Parent: root, Child: openssl},
			},
		}
		listed := changes(t, f, applied(t, f, next))
		if len(listed) == 0 || listed[0].Kind != graph.Removed || listed[0].Name != "curl" {
			t.Errorf("the listing opens with %v, want the removal of curl", spelled(listed))
		}
	})
}

func TestTheListingAndTheCountsAreOneAnswer(t *testing.T) {
	// The number on a receipt and the rows behind it are the same comparison.
	// A reader given two answers has no way to tell which is the build's.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())

		vendored := at("openssl", "1.1.1w")
		next := graph.Snapshot{
			Root: root, Components: []graph.Described{openssl, vendored, zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: openssl},
				{Parent: root, Child: vendored},
				{Parent: root, Child: zlib},
			},
		}
		scanID := applied(t, f, next)

		counted := delta(t, f, scanID)
		var listed graph.Delta
		for _, change := range changes(t, f, scanID) {
			switch change.Kind {
			case graph.Added:
				listed.Added++
			case graph.Removed:
				listed.Removed++
			case graph.Changed:
				listed.Changed++
			}
		}
		if counted != listed {
			t.Errorf("the receipt says %+v and the listing adds up to %+v", counted, listed)
		}
	})
}

func TestANameAtTwoVersionsListsBothSides(t *testing.T) {
	// What makes the row worth reading: the count says a name moved, and only
	// the versions say what a vendored tree did with it.
	each(t, func(t *testing.T, f *fixture) {
		vendored := at("openssl", "1.1.1w")
		first := graph.Snapshot{
			Root: root, Components: []graph.Described{openssl, vendored},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: openssl},
				{Parent: root, Child: vendored},
			},
		}
		applied(t, f, first)

		next := graph.Snapshot{
			Root: root, Components: []graph.Described{openssl},
			Dependencies: []graph.Dependency{{Parent: root, Child: openssl}},
		}
		listed := changes(t, f, applied(t, f, next))
		want := []string{"changed openssl [1.1.1w 3.0.11] -> [3.0.11]"}
		if strings.Join(spelled(listed), "; ") != strings.Join(want, "; ") {
			t.Errorf("the listing reads %v, want %v", spelled(listed), want)
		}
	})
}

func TestOneKindAtATimeIsAskableAndTheTotalIsOfThatKind(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())

		bumped := at("openssl", "3.0.12")
		next := graph.Snapshot{
			Root: root, Components: []graph.Described{bumped, zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: bumped},
				{Parent: root, Child: zlib},
			},
		}
		scanID := applied(t, f, next)

		listed, total, err := f.store.Changes(t.Context(), everyone(f), f.targetID, scanID,
			graph.Removed, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(listed) != 1 || listed[0].Name != "curl" {
			t.Errorf("asked for removals, %d of %d came back: %v", len(listed), total, spelled(listed))
		}
	})
}

func TestAPageIsATakenFromTheWholeAnswer(t *testing.T) {
	// The total is what the upload moved, whatever page is being read: a
	// screen that showed fifty of five hundred without saying so would report
	// a build as having changed fifty things.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())

		next := graph.Snapshot{Root: root}
		for _, name := range []string{"alpha", "beta", "gamma"} {
			arriving := at(name, "1.0")
			next.Components = append(next.Components, arriving)
			next.Dependencies = append(next.Dependencies,
				graph.Dependency{Parent: root, Child: arriving})
		}
		scanID := applied(t, f, next)

		whole := changes(t, f, scanID)
		if len(whole) != 5 {
			t.Fatalf("the upload moved %d names, want 5: %v", len(whole), spelled(whole))
		}
		page, total, err := f.store.Changes(t.Context(), everyone(f), f.targetID, scanID, "", 2, 1)
		if err != nil {
			t.Fatal(err)
		}
		if total != len(whole) {
			t.Errorf("a page of two reports a total of %d, want %d", total, len(whole))
		}
		if len(page) != 2 || page[0].Name != whole[1].Name || page[1].Name != whole[2].Name {
			t.Errorf("the second page is %v, want the second and third of %v",
				spelled(page), spelled(whole))
		}
		past, total, err := f.store.Changes(t.Context(), everyone(f), f.targetID, scanID, "", 2, 99)
		if err != nil {
			t.Fatal(err)
		}
		if len(past) != 0 || total != len(whole) {
			t.Errorf("past the end, %d rows came back with a total of %d", len(past), total)
		}
	})
}

func TestTheFirstInventoryListsNothingRatherThanEverything(t *testing.T) {
	// Every name in it is new, and none of them is a change: the first upload
	// is the first picture of a build.
	each(t, func(t *testing.T, f *fixture) {
		if listed := changes(t, f, applied(t, f, tree())); len(listed) != 0 {
			t.Errorf("the first upload listed %v, want nothing", spelled(listed))
		}
	})
}

func TestAnotherBuildsScanListsNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())
		applied(t, f, tree())
		if listed := changes(t, f, elsewhere(t, f)); len(listed) != 0 {
			t.Errorf("another build's scan listed %v, want nothing", spelled(listed))
		}
	})
}

func TestWhatAnUploadChangedIsNotReadableBySomebodyWhoDoesNotReachTheProduct(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())
		second := applied(t, f, tree())

		outsider := access.NewPerson(2, "outsider", false, nil, 0)
		_, _, err := f.store.Changes(t.Context(), outsider, f.targetID, second, "", 0, 0)
		if !errors.Is(err, access.ErrDenied) {
			t.Errorf("a subject with nothing on the product was answered: %v", err)
		}
	})
}

func TestWhatAnUploadMovedIsMeasuredAgainstWhatTheBuildHeld(t *testing.T) {
	// Forty names moving is a rebuild on an inventory of two thousand and a
	// different build on an inventory of sixty, so the size the delta is
	// against is part of the answer.
	each(t, func(t *testing.T, f *fixture) {
		vendored := at("openssl", "1.1.1w")
		first := graph.Snapshot{
			Root: root, Components: []graph.Described{openssl, vendored, curl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: openssl},
				{Parent: root, Child: vendored},
				{Parent: root, Child: curl},
			},
		}
		applied(t, f, first)

		next := tree()
		next.Components = append(next.Components, zlib)
		next.Dependencies = append(next.Dependencies, graph.Dependency{Parent: curl, Child: zlib})
		moved, answered, err := f.store.Moved(t.Context(), f.targetID, applied(t, f, next))
		if err != nil {
			t.Fatal(err)
		}
		if !answered {
			t.Fatal("a second upload was not answered for")
		}
		// Two names held before — openssl at two versions is one of them, and
		// the build's own root is none of them.
		want := graph.Movement{Delta: graph.Delta{Added: 1, Changed: 1}, Held: 2}
		if moved != want {
			t.Errorf("the upload moved %+v, want %+v", moved, want)
		}
	})
}

func TestTheFirstInventoryHasNoMovementToReport(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		moved, answered, err := f.store.Moved(t.Context(), f.targetID, applied(t, f, tree()))
		if err != nil {
			t.Fatal(err)
		}
		if answered {
			t.Errorf("the first upload reported %+v, want no answer at all", moved)
		}
	})
}

func TestANameThisUploadRemovedIsOneTheBuildHeld(t *testing.T) {
	// The size a change is measured against is the inventory as it stood
	// immediately before the scan, and a name this scan closed stood in it.
	// Counted on the far side, a build that dropped half of itself reports the
	// half it kept — and the share of an inventory that moved comes out twice
	// what it was.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())

		// curl and openssl both go, and zlib arrives in their place.
		next := graph.Snapshot{
			Root: root, Components: []graph.Described{zlib},
			Dependencies: []graph.Dependency{{Parent: root, Child: zlib}},
		}
		moved, answered, err := f.store.Moved(t.Context(), f.targetID, applied(t, f, next))
		if err != nil || !answered {
			t.Fatalf("the upload was not answered for: %v", err)
		}
		want := graph.Movement{Delta: graph.Delta{Added: 1, Removed: 2}, Held: 2}
		if moved != want {
			t.Errorf("the upload moved %+v, want %+v", moved, want)
		}
	})
}

func TestAKindOfChangeNobodyHasIsRefused(t *testing.T) {
	// Narrowed to a word this does not know, the answer would be an empty
	// listing, which reads as an upload that moved nothing.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())
		second := applied(t, f, tree())

		if _, _, err := f.store.Changes(t.Context(), everyone(f), f.targetID, second,
			"upgraded", 0, 0); err == nil {
			t.Error("a kind nobody has was answered as a listing")
		}
	})
}

func TestOneNameSpelledTwoWaysAnswersTheSameWayTwice(t *testing.T) {
	// A producer that changed how it capitalizes a dependency leaves one
	// folded name with two spellings, one per version, and nothing orders the
	// rows they come back in. Taken from whichever arrived first, the listing
	// answers differently between two identical requests — and a screen keys
	// the component link on that string, so one of the two answers leads
	// nowhere.
	each(t, func(t *testing.T, f *fixture) {
		lower := at("jinja2", "2.11.3")
		first := graph.Snapshot{
			Root: root, Components: []graph.Described{lower},
			Dependencies: []graph.Dependency{{Parent: root, Child: lower}},
		}
		applied(t, f, first)

		// The same name at a new version, written the other way.
		upper := at("Jinja2", "3.1.2")
		next := graph.Snapshot{
			Root: root, Components: []graph.Described{lower, upper},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: lower},
				{Parent: root, Child: upper},
			},
		}
		scanID := applied(t, f, next)

		listed := changes(t, f, scanID)
		if len(listed) != 1 {
			t.Fatalf("the upload moved %d names, want one: %v", len(listed), spelled(listed))
		}
		// The spelling is decided rather than taken from whichever row came
		// back first: the smallest of them, which is the same answer on every
		// engine and on every read. Asserted as the value rather than as
		// "twice the same", because two reads in one test see one order.
		if listed[0].Name != "Jinja2" {
			t.Errorf("the listing names it %q, want the spelling this picks "+
				"whatever order the rows arrive in", listed[0].Name)
		}
	})
}
