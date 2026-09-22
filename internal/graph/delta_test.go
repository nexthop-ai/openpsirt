package graph_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// What a build's inventory gained, lost and moved between one scan and the one
// before it. These pin the comparison rather than the surface: the intervals
// are read as history rather than as what is present, and every rule about
// which side of a scan a row stands on is a place a wrong inequality passes a
// test that asks only what is open.

// delta asks for one scan's answer and fails where there is none.
func delta(t *testing.T, f *fixture, scanID int64) graph.Delta {
	t.Helper()
	answers, err := f.store.Deltas(t.Context(), everyone(f), f.targetID, []int64{scanID})
	if err != nil {
		t.Fatal(err)
	}
	answer, ok := answers[scanID]
	if !ok {
		t.Fatalf("scan %d is not in the answer", scanID)
	}
	return answer
}

// applied files a snapshot as a new scan and returns that scan.
func applied(t *testing.T, f *fixture, snap graph.Snapshot) int64 {
	t.Helper()
	scanID := f.scan(t)
	if _, err := f.store.Apply(t.Context(), f.targetID, scanID, snap); err != nil {
		t.Fatal(err)
	}
	return scanID
}

func TestTheFirstInventoryHasNothingToDifferFrom(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		first := applied(t, f, tree())
		answers, err := f.store.Deltas(t.Context(), everyone(f), f.targetID, []int64{first})
		if err != nil {
			t.Fatal(err)
		}
		if answer, ok := answers[first]; ok {
			t.Errorf("the first scan reported %+v, want no answer at all", answer)
		}
	})
}

func TestAComponentTheInventoryDidNotHoldIsAdded(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())

		next := tree()
		next.Components = append(next.Components, zlib)
		next.Dependencies = append(next.Dependencies, graph.Dependency{Parent: curl, Child: zlib})

		if got, want := delta(t, f, applied(t, f, next)), (graph.Delta{Added: 1}); got != want {
			t.Errorf("one arrival reported %+v, want %+v", got, want)
		}
	})
}

func TestAComponentTheInventoryStopsDescribingIsRemoved(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())

		// curl goes, and openssl stays because the product still names it.
		next := graph.Snapshot{
			Root: root, Components: []graph.Described{openssl},
			Dependencies: []graph.Dependency{{Parent: root, Child: openssl}},
		}
		if got, want := delta(t, f, applied(t, f, next)), (graph.Delta{Removed: 1}); got != want {
			t.Errorf("one departure reported %+v, want %+v", got, want)
		}
	})
}

func TestANameAtANewVersionMovedRatherThanArrivedAndWent(t *testing.T) {
	// The reason the comparison is by name. Counted as components, the
	// ordinary case — a dependency upgraded — reads as one arrival and one
	// departure, and a build that upgraded three things reads as six changes.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())

		bumped := at("openssl", "3.0.12")
		next := graph.Snapshot{
			Root: root, Components: []graph.Described{bumped, curl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: curl},
				{Parent: root, Child: bumped},
				{Parent: curl, Child: bumped},
			},
		}
		if got, want := delta(t, f, applied(t, f, next)), (graph.Delta{Changed: 1}); got != want {
			t.Errorf("an upgrade reported %+v, want %+v", got, want)
		}
	})
}

func TestANameAlreadyShippedAtAnotherVersionMovedRatherThanArrived(t *testing.T) {
	// A name at two versions at once is what a vendored tree produces, and it
	// is the case a comparison of name sets alone gets wrong: the name was
	// there before and is there after, so nothing arrived and nothing went.
	each(t, func(t *testing.T, f *fixture) {
		old := at("openssl", "1.1.1w")
		first := graph.Snapshot{
			Root: root, Components: []graph.Described{openssl, old, curl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: openssl},
				{Parent: curl, Child: old},
				{Parent: root, Child: curl},
			},
		}
		applied(t, f, first)

		// The old copy goes and the new one stays. One name, one side fewer
		// versions.
		next := graph.Snapshot{
			Root: root, Components: []graph.Described{openssl, curl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: openssl},
				{Parent: root, Child: curl},
			},
		}
		if got, want := delta(t, f, applied(t, f, next)), (graph.Delta{Changed: 1}); got != want {
			t.Errorf("a second copy going reported %+v, want %+v", got, want)
		}
	})
}

func TestARebuildThatMovedNothingReportsNoChangeRatherThanNoAnswer(t *testing.T) {
	// A scan that changed nothing and a scan this cannot answer for are
	// different statements, and zero is only the first of them.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())
		if got, want := delta(t, f, applied(t, f, tree())), (graph.Delta{}); got != want {
			t.Errorf("an identical rebuild reported %+v, want %+v", got, want)
		}
	})
}

func TestTheProductsOwnVersionIsNotOneOfItsComponents(t *testing.T) {
	// The root carries a build stamp and moves every night. Counted, every
	// build would report one name changed and nothing else would be visible
	// next to it.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())
		next := rebuilt(tree(), "2.4.0-20260829.010101")
		if got, want := delta(t, f, applied(t, f, next)), (graph.Delta{}); got != want {
			t.Errorf("a rebuild of the product alone reported %+v, want %+v", got, want)
		}
	})
}

func TestAComponentSharingTheProductsNameIsStillNotTheProduct(t *testing.T) {
	// The root is excluded from both sides of the comparison and not only
	// from what can have moved. An image that ships a package named after
	// itself is the case that tells the two exclusions apart: the root node
	// carries the name and no version, so counted on both sides it turns a
	// departure into a version set that merely moved.
	each(t, func(t *testing.T, f *fixture) {
		named := at("sonic", "1.0")
		first := graph.Snapshot{
			Root: root, Components: []graph.Described{named, curl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: curl},
				{Parent: curl, Child: named},
			},
		}
		applied(t, f, first)

		next := graph.Snapshot{
			Root: root, Components: []graph.Described{curl},
			Dependencies: []graph.Dependency{{Parent: root, Child: curl}},
		}
		if got, want := delta(t, f, applied(t, f, next)), (graph.Delta{Removed: 1}); got != want {
			t.Errorf("a package named after the product reported %+v, want %+v", got, want)
		}
	})
}

func TestEachScanOnAPageIsAnsweredAgainstTheOneBeforeIt(t *testing.T) {
	// The surface asking is a page of receipts, so the statement answers a
	// set. A scan's numbers are against its own predecessor and not against
	// the newest.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())

		grown := tree()
		grown.Components = append(grown.Components, zlib)
		grown.Dependencies = append(grown.Dependencies,
			graph.Dependency{Parent: curl, Child: zlib})
		second := applied(t, f, grown)

		bumped := at("zlib", "1.3.1")
		moved := tree()
		moved.Components = append(moved.Components, bumped)
		moved.Dependencies = append(moved.Dependencies,
			graph.Dependency{Parent: curl, Child: bumped})
		third := applied(t, f, moved)

		shrunk := tree()
		fourth := applied(t, f, shrunk)

		answers, err := f.store.Deltas(t.Context(), everyone(f), f.targetID,
			[]int64{second, third, fourth})
		if err != nil {
			t.Fatal(err)
		}
		want := map[int64]graph.Delta{
			second: {Added: 1}, third: {Changed: 1}, fourth: {Removed: 1},
		}
		for scanID, expected := range want {
			if got := answers[scanID]; got != expected {
				t.Errorf("scan %d reported %+v, want %+v", scanID, got, expected)
			}
		}
		if len(answers) != len(want) {
			t.Errorf("%d scans answered, want %d", len(answers), len(want))
		}
	})
}

func TestAScanOfAnotherBuildIsAnsweredForByNothing(t *testing.T) {
	// The scans asked about are read from the scan table under this build, so
	// an identifier that belongs elsewhere is absent from the answer. Counted
	// against these rows it would come back as three zeros, which reads as an
	// upload of this build that changed nothing.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())
		applied(t, f, tree())

		other := elsewhere(t, f)
		mine, err := f.store.Deltas(t.Context(), everyone(f), f.targetID, []int64{other})
		if err != nil {
			t.Fatal(err)
		}
		if answer, ok := mine[other]; ok {
			t.Errorf("another build's scan was answered for: %+v", answer)
		}
	})
}

func TestAnInventoryIsNotReadableBySomebodyWhoDoesNotReachTheProduct(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())
		second := applied(t, f, tree())

		outsider := access.NewPerson(2, "outsider", false, nil, 0)
		if _, err := f.store.Deltas(t.Context(), outsider, f.targetID, []int64{second}); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a subject with nothing on the product was answered: %v", err)
		}
	})
}

// elsewhere is a scan of a second build of the same product, applied, so that
// a comparison can be asked the wrong build's question.
func elsewhere(t *testing.T, f *fixture) int64 {
	t.Helper()
	ctx := t.Context()
	cat := catalog.NewStore(f.db.DB)
	variant, err := cat.DeclareVariant(ctx, *f.scope.ProductID, "other", true)
	if err != nil {
		t.Fatal(err)
	}
	target, err := cat.TargetFor(ctx, *f.scope.StreamID, variant.ID)
	if err != nil {
		t.Fatal(err)
	}

	f.seq++
	f.built = f.built.Add(time.Hour)
	rec, outcome, err := f.scans.Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: fmt.Sprintf("other-%d", f.seq),
		BuiltAt: f.built, ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record a scan of the other build: outcome %v, err %v", outcome, err)
	}
	if _, err := f.store.Apply(ctx, target.ID, rec.ID, tree()); err != nil {
		t.Fatal(err)
	}
	return rec.ID
}
