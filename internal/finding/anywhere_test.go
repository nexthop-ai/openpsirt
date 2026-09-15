package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The findings list across every product somebody may see.
//
// What it must get right is the narrowing: a page spanning products is exactly
// where filtering afterwards gets forgotten, and the total leaks even when no
// row is shown. Each of those is watched failing.
func TestTheListAcrossProductsAnswersOnlyForWhatIsHeld(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
		}); err != nil {
			t.Fatal(err)
		}
		// The same library carrying the same issue in a second product, which
		// is a second piece of work: it is decided separately, by different
		// people, under a different line.
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(t.Context(), elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		other := f.productOf(t, elsewhere)

		// Somebody who reads only the first product sees only its rows, and
		// the total agrees with the page.
		here := f.holding(t, access.PublicRead)
		rows, total, err := f.store.Anywhere(t.Context(), here, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(rows) != 2 {
			t.Fatalf("reading one product answered %d rows and counted %d, wanted two of each",
				len(rows), total)
		}
		for _, row := range rows {
			if row.Product != "sonic" {
				t.Errorf("a product they hold nothing on appeared: %s", row.Product)
			}
		}

		// Somebody who reads both gets three rows: the same issue in the same
		// component of two products is two pieces of work.
		both := f.holdingIn(t, []int64{f.productID, other}, access.PublicRead)
		rows, total, err = f.store.Anywhere(t.Context(), both, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if total != 3 || len(rows) != 3 {
			t.Fatalf("reading both answered %d rows and counted %d, wanted three of each",
				len(rows), total)
		}
		products := map[string]int{}
		for _, row := range rows {
			products[row.Product]++
			if row.Vulnerability == "" || row.Component == "" {
				t.Errorf("a row came back unnamed: %+v", row)
			}
		}
		if products["sonic"] != 2 || products["hedgehog"] != 1 {
			t.Errorf("rows landed as %v, wanted two in sonic and one in hedgehog", products)
		}

		// Paging is stable and the total is the whole population rather than
		// the page: a total counted over the page is the number people quote
		// while the list beside it shows something else.
		// A row at a time, which is where a boundary drops one and repeats
		// another. Two of these three are the same issue in the same
		// component of two products — identical on everything the
		// per-product list tie-breaks on — so the product has to be part of
		// the order or their positions are unspecified.
		seen := map[string]bool{}
		for at := 0; at < 3; at++ {
			one, count, err := f.store.Anywhere(t.Context(), both, 1, at, finding.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			if count != 3 || len(one) != 1 {
				t.Fatalf("row %d of a total of %d came back as %d rows", at, count, len(one))
			}
			key := one[0].Product + " " + one[0].Vulnerability + " " + one[0].Component
			if seen[key] {
				t.Errorf("%s appeared twice while paging one row at a time", key)
			}
			seen[key] = true
		}
		if len(seen) != 3 {
			t.Errorf("paging one at a time held %d distinct rows, wanted 3", len(seen))
		}

		// A filter narrows the page and the total through the same clause.
		kept, keptTotal, err := f.store.Anywhere(t.Context(), both, 50, 0,
			finding.Filter{Components: []string{libnl.Name}})
		if err != nil {
			t.Fatal(err)
		}
		if len(kept) != 2 || keptTotal != 2 {
			t.Errorf("narrowing to one component kept %d rows and counted %d, wanted two of each",
				len(kept), keptTotal)
		}
		none, noneTotal, err := f.store.Anywhere(t.Context(), both, 50, 0,
			finding.Filter{Components: []string{"nothing-called-this"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(none) != 0 || noneTotal != 0 {
			t.Errorf("a component nothing is called kept %d rows and counted %d",
				len(none), noneTotal)
		}

		// A subtree is a walk over one build's edges, so it is refused rather
		// than answered from whichever build sorted first.
		component := f.componentID(t, libnl.Name)
		if _, _, err := f.store.Anywhere(t.Context(), both, 50, 0,
			finding.Filter{Beneath: &component}); err == nil {
			t.Error("a subtree was answered across products")
		}
	})
}

// Each product's own line applies, because a line is a claim about what is
// worth an afternoon here.
func TestTheListAcrossProductsKeepsEachProductsLine(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			lowly("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(t.Context(), elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{lowly("CVE-2026-2", libnl)}); err != nil {
			t.Fatal(err)
		}
		other := f.productOf(t, elsewhere)
		both := f.holdingIn(t, []int64{f.productID, other}, access.PublicRead)

		before, beforeTotal, err := f.store.Anywhere(t.Context(), both, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(before) != 2 || beforeTotal != 2 {
			t.Fatalf("with no line set, %d rows and a total of %d", len(before), beforeTotal)
		}

		// The second product decides low findings are not worth triaging. The
		// first says nothing, so its row stays.
		if err := catalog.NewStore(f.db.DB).SetTriageFloor(t.Context(), other, "high"); err != nil {
			t.Fatal(err)
		}
		after, afterTotal, err := f.store.Anywhere(t.Context(), both, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != 1 || afterTotal != 1 {
			t.Fatalf("one product's line left %d rows and a total of %d, wanted one of each: %+v",
				len(after), afterTotal, after)
		}
		if after[0].Product != "sonic" {
			t.Errorf("the row that survived is in %s, wanted the product that set no line",
				after[0].Product)
		}

		// Asking for what is below the line brings it back, so the row is
		// hidden rather than gone.
		below, belowTotal, err := f.store.Anywhere(t.Context(), both, 50, 0,
			finding.Filter{BelowFloor: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(below) != 2 || belowTotal != 2 {
			t.Errorf("asking below the line answered %d rows and counted %d, wanted two of each",
				len(below), belowTotal)
		}
	})
}

// lowly is one reported issue nothing would call urgent, for the line to hide.
func lowly(id string, component graph.Described) finding.Reported {
	return finding.Reported{
		Issue:     finding.Named{Identifier: id, Severity: "low"},
		Component: component,
	}
}

// The two lists say the same thing about the same row.
//
// They are one screen with a product picked or not, and they were assembled by
// two functions — so what one of them said about an issue and the other did
// not was a difference nobody chose. The line of the issue's own words and the
// source package it was built from were both being read for the page here and
// then dropped, which is the failure being watched: not a missing lookup, a
// missing assignment. The marks people put on a row were the third: the filter
// here already took them while no row drew one.
func TestBothListsSayWhatTheIssueIs(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// A binary package built from a source package of another name, which
		// is the case the source column exists for.
		binary := libnl
		binary.UpstreamName, binary.UpstreamVersion = "libnl3", "3.7.0"
		snap := twoConsumers()
		snap.Components = []graph.Described{swss, teamd, binary}
		snap.Dependencies = []graph.Dependency{
			{Parent: root, Child: swss}, {Parent: swss, Child: binary},
		}
		f.shipped(t, snap)
		said := "The parser accepts a length nobody bounded.\nA second line nothing shows."
		reported := found("CVE-2026-9", binary)
		reported.Issue.Description = said
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{reported}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)

		within, _, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		across, _, err := f.store.Anywhere(t.Context(), who, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(within) != 1 || len(across) != 1 {
			t.Fatalf("%d rows in the product and %d across, wanted one of each",
				len(within), len(across))
		}
		// Both halves are asserted against a value rather than against each
		// other alone: two empty strings agree, and would pass this while
		// saying nothing.
		if within[0].Summary == "" || within[0].Source == "" {
			t.Fatalf("the product's own list says %q and %q, so this compares nothing",
				within[0].Summary, within[0].Source)
		}
		if across[0].Summary != within[0].Summary {
			t.Errorf("across products the row says %q and within one it says %q",
				across[0].Summary, within[0].Summary)
		}
		if across[0].Source != within[0].Source {
			t.Errorf("across products the source package is %q and within one it is %q",
				across[0].Source, within[0].Source)
		}

		// And the words people put on it. A mark is for finding the work
		// again in a list, so a list that does not draw one is a mark nobody
		// sees — and the filter here already takes them, which is the half
		// that made the other half's absence hard to notice.
		marker := f.someoneElse(t, access.PublicTriage)
		if err := f.store.TagIt(t.Context(), marker, f.productID,
			f.issueID(t, "CVE-2026-9"), f.componentID(t, binary.Name),
			"Waiting On Vendor"); err != nil {
			t.Fatal(err)
		}
		marked, _, err := f.store.Anywhere(t.Context(), who, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(marked) != 1 || len(marked[0].Tags) != 1 ||
			marked[0].Tags[0] != "Waiting On Vendor" {
			t.Errorf("across products the row is marked %q, wanted the word that was put on it",
				marked[0].Tags)
		}

		// And the rating in force, which is what reassessing an issue is for.
		// The two lists assembled their rows separately and this one named the
		// severity the report published, so an issue rated worse here read as
		// critical on the product's list and low on the one above it — the
		// list somebody arrives at before they have picked a product.
		f.recorded(t, 1, "someone")
		if _, err := f.store.Assess(t.Context(), f.holding(t, access.PublicTriage), f.productID,
			f.issue(t, "CVE-2026-9"), "critical",
			"Reachable from the network in how we ship it."); err != nil {
			t.Fatal(err)
		}
		rated, _, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		ratedAcross, _, err := f.store.Anywhere(t.Context(), who, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rated) != 1 || rated[0].Severity != "critical" {
			t.Fatalf("the product's own list says %v, so this compares nothing", rated)
		}
		if len(ratedAcross) != 1 || ratedAcross[0].Severity != rated[0].Severity {
			t.Errorf("across products the row is rated %v and within one it is %q",
				ratedAcross, rated[0].Severity)
		}
	})
}

func TestAGroupWhosePlacesDisagreeSaysSo(t *testing.T) {
	// A row is an issue at a component across the builds that ship it, and
	// asking what upstream did is asking about the whole of that. Where the
	// builds disagree there is no single answer, which is what the mixed state
	// is for — the filter selected exactly that set and every row it returned
	// claimed a definite state, with a version taken from whichever of the
	// disagreeing places sorted first.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		// A second branch of the same product where the scanner says upstream
		// has published nothing.
		branch := f.anotherBranchOf(t, f.productID, "2026.06")
		f.shippedTo(t, branch, twoConsumers())
		nothing := found("CVE-2026-1", libnl)
		nothing.FixState, nothing.FixedIn = finding.NoFix, ""
		if _, err := f.store.Apply(ctx, branch, f.runOn(t, branch),
			[]finding.Reported{nothing}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicRead)
		rows, _, err := f.store.Anywhere(ctx, who, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("%d rows, want the one issue at the one component", len(rows))
		}
		if rows[0].FixState != finding.FixMixed {
			t.Errorf("a group whose builds disagree says upstream %q", rows[0].FixState)
		}
		if rows[0].FixedIn != "" {
			t.Errorf("it names %q as the version that fixes it, which only one of its "+
				"builds says", rows[0].FixedIn)
		}

		// And the filter that selects the set answers with the set.
		narrowed, total, err := f.store.Anywhere(ctx, who, 50, 0,
			finding.Filter{FixStates: []finding.FixState{finding.FixMixed}})
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(narrowed) != 1 || narrowed[0].FixState != finding.FixMixed {
			t.Errorf("narrowing to mixed answered %d of %d: %+v", len(narrowed), total, narrowed)
		}
	})
}
