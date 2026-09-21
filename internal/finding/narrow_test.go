package finding_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The filters that narrow a findings list by something other than how bad an
// issue is: what kind of package carries it, what holds that package, and how
// far it has been decided.
//
// Every one of them narrows the page *and* the total through the same clause,
// which is what keeps the number beside a list from counting something else —
// so each case below asserts both.
func TestNarrowingByPackageKind(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss), found("CVE-2026-3", teamd),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		all, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if total == 0 || len(all) == 0 {
			t.Fatal("wanted findings to narrow")
		}

		// The fixture's components are Debian packages, so the kind they are
		// keeps everything and a kind they are not keeps nothing. Both
		// directions, because a filter that never excludes and a filter that
		// excludes everything look the same from one of them.
		kept, keptTotal, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Ecosystems: []string{"deb"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(kept) != len(all) || keptTotal != total {
			t.Errorf("asking for the kind they are kept %d of %d (total %d of %d)",
				len(kept), len(all), keptTotal, total)
		}

		none, noneTotal, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Ecosystems: []string{"golang"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(none) != 0 || noneTotal != 0 {
			t.Errorf("asking for a kind nothing is kept %d rows and counted %d",
				len(none), noneTotal)
		}
	})
}

func TestNarrowingByWhatHoldsIt(t *testing.T) {
	// A place records what pulls a component in, so "what is inside this
	// container" is a question about consumers — and what the build holds
	// directly is the places that have none. The two together are every place,
	// which is what makes them worth asserting against each other.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss), found("CVE-2026-3", teamd),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		_, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}

		// The consumer's own name. `swss` is what the Go variable is called;
		// the component is `libswsscommon`, and filtering on the variable's
		// name matched nothing — which passed every assertion below for the
		// wrong reason, because "narrowed to a subset" and "narrowed to
		// nothing" are both fewer than everything.
		inside, insideTotal, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Under: swss.Name})
		if err != nil {
			t.Fatal(err)
		}
		if insideTotal >= total || insideTotal == 0 {
			t.Errorf("naming one consumer kept %d of %d, want some but not all",
				insideTotal, total)
		}
		if insideTotal != len(inside) {
			t.Errorf("the total counts %d and the page has %d; they are counted differently",
				insideTotal, len(inside))
		}

		// A consumer nothing is under keeps nothing rather than everything,
		// which is the failure a filter silently not applied would look like.
		_, absent, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Under: "no-such-container"})
		if err != nil {
			t.Fatal(err)
		}
		if absent != 0 {
			t.Errorf("a consumer nothing sits under kept %d", absent)
		}

		// The build's direct holdings are the other half. Together they are
		// every place, which is the assertion worth making: a filter that
		// quietly kept nothing would satisfy either half alone.
		_, direct, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{UnderTheBuild: true})
		if err != nil {
			t.Fatal(err)
		}
		if direct == 0 {
			t.Error("nothing reads as held by the build itself")
		}
	})
}

func TestAClaimInAnotherProductDoesNotDecideThisOne(t *testing.T) {
	// A place identity is a hash of a consumer and a component and carries no
	// product, and an issue is one row for the whole deployment — so anything
	// correlating a place to a decision without naming the product matches
	// every product there is.
	//
	// That is two failures at once. A reader is told a claim is pending in a
	// product they may not be able to see, and their own screen says "waiting"
	// when nothing here is waiting. This writes a real decision in a real
	// second product, at the same place and about the same issue, and asserts
	// it moves nothing here.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", swss),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		// A second product, declared properly: the row has foreign keys to
		// product and person, so inventing numbers would fail the write rather
		// than test anything.
		elsewhere, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var issueID int64
		if err := f.db.DB.NewSelect().TableExpr("\"vulnerability\" AS \"v\"").
			Column("v.id").Where("v.identifier = ?", "CVE-2026-1").
			Scan(ctx, &issueID); err != nil {
			t.Fatal(err)
		}

		// The place a component sitting directly under the build hashes to,
		// which is the same string in every product — that being the point.
		// Live, and keyed on the version shipping here, so that the product
		// is the only thing keeping it from standing: a claim that failed to
		// match on its versions would leave a missing product condition
		// unexercised.
		place := finding.PlaceIdentity(swss.Name, "")
		if _, err := f.db.DB.NewInsert().
			Model(&map[string]any{
				"claim_id":         claimBy(t, f.db, somebody.ID),
				"product_id":       elsewhere.ID,
				"vulnerability_id": issueID,
				"place_identity":   place,
				"visibility":       "public",
				"state":            "proposed",
				"needs_approval":   true, "stands_at_any_version": false,
				"proposed_by":                somebody.ID,
				"proposed_at":                time.Now().UTC(),
				"component_upstream_version": swss.Version,
				"live_key":                   "elsewhere-live-key",
			}).
			TableExpr("\"decision\"").Exec(ctx); err != nil {
			// A row this test cannot write is a reason to fail: skipping would
			// make it green in exactly the case where it proves nothing.
			t.Fatalf("could not record a claim in another product: %v", err)
		}

		_, waiting, err := f.store.Groups(ctx, who, f.scope, 50, 0,
			finding.Filter{States: []string{"waiting"}})
		if err != nil {
			t.Fatal(err)
		}
		if waiting != 0 {
			t.Errorf("a claim in another product made %d rows here read as waiting", waiting)
		}
		_, undecided, err := f.store.Groups(ctx, who, f.scope, 50, 0,
			finding.Filter{States: []string{"undecided"}})
		if err != nil {
			t.Fatal(err)
		}
		if undecided != 1 {
			t.Errorf("%d rows read as undecided, want the 1 that nobody here has decided",
				undecided)
		}

		// And the finding's own screen, which names the decision standing at
		// each place, names nothing: it showed the other product's claim as
		// standing here, an identifier the reader could not open.
		open := f.open(t)
		evidence, err := f.store.Detail(ctx, who, f.target, open[0].VulnerabilityID, open[0].ComponentID)
		if err != nil {
			t.Fatal(err)
		}
		for _, sitting := range evidence.Places {
			if sitting.Decision != nil {
				t.Errorf("a claim in another product reads as decision %d standing here",
					*sitting.Decision)
			}
		}
	})
}

func TestALapsedPlaceDecidedAgainReadsAsWaiting(t *testing.T) {
	// Lapsed means a decision here stopped applying and nothing replaced it.
	// Once somebody makes the claim again, the place is waiting — which is
	// what the row said, while the filter still listed it under lapsed: it
	// asked only that something had lapsed and nothing was approved. A filter
	// has to find a row by the word the row reads.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", swss),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		place := finding.PlaceIdentity(swss.Name, "")
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-1"), place, "lapsed", "0.9.0", "")
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-1"), place, "proposed", swss.Version, "again")

		groups, _, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 || groups[0].State != "waiting" {
			t.Fatalf("a lapsed place claimed again reads as %+v, want one row waiting", groups)
		}
		_, lapsed, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{States: []string{"lapsed"}})
		if err != nil {
			t.Fatal(err)
		}
		if lapsed != 0 {
			t.Errorf("lapsed kept %d rows that read as waiting", lapsed)
		}
		_, waiting, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{States: []string{"waiting"}})
		if err != nil {
			t.Fatal(err)
		}
		if waiting != 1 {
			t.Errorf("waiting kept %d, want the 1 row that reads as waiting", waiting)
		}
	})
}

func TestALiveDecisionCoversOnlyTheVersionsItWasKeyedOn(t *testing.T) {
	// A decision is a claim about a place at the versions it was keyed on,
	// and it lapses by those versions moving. Two builds of one product can
	// ship the same place at different versions, and the one that moved is
	// exactly the one the decision no longer covers — everything that asks
	// whether a decision applies says so, and the list's state, its filter and
	// the finding's screen were matching by place alone and saying "agreed".
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		directly := func(library graph.Described) graph.Snapshot {
			return graph.Snapshot{
				Root: root, Components: []graph.Described{library},
				Dependencies: []graph.Dependency{{Parent: root, Child: library}},
			}
		}
		f.shipped(t, directly(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		other := f.anotherBuild(t, "202411")
		f.shippedTo(t, other, directly(libnlNew))
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-1", libnlNew),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Approved against the older version, in the build that ships it.
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-1"),
			finding.PlaceIdentity(libnl.Name, ""), "approved", libnl.Version, "old")

		reads := func(target int64, want string) {
			t.Helper()
			groups, _, err := f.store.Groups(ctx, who, f.scopeOf(t, target), 50, 0, finding.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			if len(groups) != 1 || groups[0].State != want {
				t.Errorf("build %d reads as %+v, want one row %q", target, groups, want)
			}
			_, agreed, err := f.store.Groups(ctx, who, f.scopeOf(t, target), 50, 0, finding.Filter{States: []string{"agreed"}})
			if err != nil {
				t.Fatal(err)
			}
			if kept := want == "agreed"; (agreed == 1) != kept {
				t.Errorf("build %d: agreed kept %d rows, want %v", target, agreed, kept)
			}
		}
		decided := func(target int64) int {
			t.Helper()
			var open []finding.Finding
			if err := f.db.DB.NewSelect().Model(&open).
				Where("target_id = ?", target).Where("closed_at IS NULL").Scan(ctx); err != nil {
				t.Fatal(err)
			}
			evidence, err := f.store.Detail(ctx, who, target, open[0].VulnerabilityID, open[0].ComponentID)
			if err != nil {
				t.Fatal(err)
			}
			if len(evidence.Places) != 1 {
				t.Fatalf("build %d sits at %d places, want 1", target, len(evidence.Places))
			}
			n := 0
			for _, sitting := range evidence.Places {
				if sitting.Decision != nil {
					n++
				}
			}
			return n
		}

		reads(f.target, "agreed")
		if n := decided(f.target); n != 1 {
			t.Errorf("the build the decision was made against shows %d of 1 places decided", n)
		}
		reads(other, "undecided")
		if n := decided(other); n != 0 {
			t.Errorf("the build that moved on shows %d of 1 places decided, want 0", n)
		}
	})
}

// decided writes one decision of this product at a place, keyed on a
// component version, as the triage store would have written it. Live where
// the state is one a live claim can hold; a lapsed or withdrawn row holds no
// key, which is what says it no longer applies.
func (f *fixture) decided(t *testing.T, by, issueID int64, place, state, componentVersion, key string) {
	t.Helper()
	row := map[string]any{
		"claim_id":   claimBy(t, f.db, by),
		"product_id": f.productID, "vulnerability_id": issueID,
		"place_identity": place, "visibility": "public",
		"state":          state,
		"needs_approval": true, "stands_at_any_version": false, "proposed_by": by,
		"proposed_at":                time.Now().UTC(),
		"component_upstream_version": componentVersion,
	}
	if key != "" {
		// Short, and not the place: the column holds sixty-four characters,
		// which a place identity fills on its own.
		row["live_key"] = key
	}
	if _, err := f.db.DB.NewInsert().Model(&row).TableExpr("\"decision\"").Exec(t.Context()); err != nil {
		t.Fatalf("record a %s claim: %v", state, err)
	}
}

func TestEachDecisionStateSelectsWhatItNames(t *testing.T) {
	// The states asserted positively rather than by all being empty.
	//
	// Nothing-is-decided is a fixture where "correct" and "always false" look
	// identical, so three of the four states were pinned by a condition that
	// could have been anything. This records a claim at a place and walks it:
	// proposed reads as waiting, approved and live reads as agreed, and a
	// claim that stopped applying reads as lapsed and not as agreed.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", swss),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var issueID int64
		if err := f.db.DB.NewSelect().TableExpr("\"vulnerability\" AS \"v\"").
			Column("v.id").Where("v.identifier = ?", "CVE-2026-1").
			Scan(ctx, &issueID); err != nil {
			t.Fatal(err)
		}
		place := finding.PlaceIdentity(swss.Name, "")

		record := func(state string, live bool) {
			t.Helper()
			if _, err := f.db.DB.NewDelete().Table("decision").
				Where("vulnerability_id = ?", issueID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			row := map[string]any{
				"claim_id":   claimBy(t, f.db, somebody.ID),
				"product_id": f.productID, "vulnerability_id": issueID,
				"place_identity": place, "visibility": "public",
				"state":          state,
				"needs_approval": true, "stands_at_any_version": false, "proposed_by": somebody.ID,
				"proposed_at": time.Now().UTC(),
			}
			if live {
				// The test for a claim standing here: a key, and the
				// version the claim was made against being the one shipping.
				row["live_key"] = state + "-live-key"
				row["component_upstream_version"] = swss.Version
			}
			if _, err := f.db.DB.NewInsert().Model(&row).
				TableExpr("\"decision\"").Exec(ctx); err != nil {
				t.Fatalf("record a %s claim: %v", state, err)
			}
		}
		count := func(state string) int {
			t.Helper()
			_, n, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{States: []string{state}})
			if err != nil {
				t.Fatalf("%s: %v", state, err)
			}
			return n
		}
		// The row says the same word the filter would find it by, from the
		// same counts in the same statement.
		said := func(want string) {
			t.Helper()
			groups, _, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			for _, group := range groups {
				if group.Vulnerability == "CVE-2026-1" && group.State != want {
					t.Errorf("the row reads as %q, want %q", group.State, want)
				}
			}
		}

		said("undecided")
		// A proposed row that holds no key covers nothing: a proposal is live
		// until it is withdrawn or lapses, and both release the key. So the
		// place stands undecided — and the row and the filter say the same
		// thing about it, which is what they exist to do. A row drawing no
		// word at all while the filter puts the group in the undecided
		// bucket leaves a reader looking at a list whose own state column
		// is blank.
		record("proposed", false)
		said("undecided")
		if n := count("undecided"); n != 1 {
			t.Errorf("a claim that holds nothing: undecided kept %d, want 1", n)
		}
		if n := count("waiting"); n != 0 {
			t.Errorf("a claim that holds nothing is not waiting, yet waiting kept %d", n)
		}
		record("proposed", true)
		said("waiting")
		if n := count("waiting"); n != 1 {
			t.Errorf("a proposed claim: waiting kept %d, want 1", n)
		}
		if n := count("undecided"); n != 0 {
			t.Errorf("a proposed claim: undecided kept %d, want 0", n)
		}
		if n := count("agreed"); n != 0 {
			t.Errorf("a proposed claim is not agreed, yet agreed kept %d", n)
		}

		record("approved", true)
		said("agreed")
		if n := count("agreed"); n != 1 {
			t.Errorf("an approved live claim: agreed kept %d, want 1", n)
		}
		if n := count("waiting"); n != 0 {
			t.Errorf("an approved claim is not waiting, yet waiting kept %d", n)
		}

		record("lapsed", false)
		said("lapsed")
		if n := count("lapsed"); n != 1 {
			t.Errorf("a lapsed claim: lapsed kept %d, want 1", n)
		}
		if n := count("agreed"); n != 0 {
			t.Errorf("a lapsed claim is not agreed, yet agreed kept %d", n)
		}

		// An approval that has stopped standing is not an agreement. The
		// claim was agreed to and then withdrawn, which releases the key, and
		// the row keeps its word: without the live key on the count a
		// judgment taken back eighteen months ago goes on answering for its
		// place, and the row and the filter answer it the same way because
		// they are counting through one condition.
		record("approved", false)
		said("undecided")
		if n := count("agreed"); n != 0 {
			t.Errorf("an approval that no longer stands read as agreed: %d", n)
		}

		// And a claim that was withdrawn long ago answers for nothing: it is
		// not live, so the place is undecided again.
		record("withdrawn", false)
		if n := count("agreed"); n != 0 {
			t.Errorf("a withdrawn claim read as agreed: %d", n)
		}
	})
}

func TestNarrowingByHowFarDecided(t *testing.T) {
	// A group covers every place an issue sits at in one component, so its
	// state is a statement about all of them: undecided means no place has a
	// decision, not that one of them does not.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		_, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}

		// Nothing has been decided, so every group is undecided and none is
		// answered. Both asserted: "undecided keeps everything" alone is what
		// a clause that never runs also looks like.
		_, undecided, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{States: []string{"undecided"}})
		if err != nil {
			t.Fatal(err)
		}
		if undecided != total {
			t.Errorf("nothing is decided, so undecided should be all %d, got %d",
				total, undecided)
		}
		for _, state := range []string{"agreed", "waiting", "lapsed"} {
			_, n, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
				finding.Filter{States: []string{state}})
			if err != nil {
				t.Fatalf("%s: %v", state, err)
			}
			if n != 0 {
				t.Errorf("nothing is decided, so %q should keep none, got %d", state, n)
			}
		}
	})
}

// claimBy records the action a directly written decision belongs to. Every
// decision is one row of a claim, and a row written without one is refused.
//
// The outcome is the claim's, not the row's: one act is one argument. What
// these tests vary is where a judgment lands and what state it is in, so the
// argument itself is the same dismissal every time.
func claimBy(t *testing.T, db *database.DB, personID int64) int64 {
	t.Helper()
	return claimSaying(t, db, personID, "not-applicable")
}

// claimSaying records a claim with one outcome, for a test that turns on which
// judgment was made rather than on where it landed.
func claimSaying(t *testing.T, db *database.DB, personID int64, outcome string) int64 {
	t.Helper()
	ctx := context.Background()
	if _, err := db.DB.NewInsert().
		Model(&map[string]any{
			"kind": "finding", "proposed_by": personID, "proposed_at": time.Now().UTC(),
			"outcome": outcome,
		}).
		TableExpr("\"claim\"").Exec(ctx); err != nil {
		t.Fatalf("record a claim: %v", err)
	}
	var id int64
	if err := db.DB.NewSelect().TableExpr("\"claim\"").ColumnExpr("MAX(id)").Scan(ctx, &id); err != nil {
		t.Fatalf("read the claim back: %v", err)
	}
	return id
}

func TestSearchingFindsAnIssueByNameAndByAlias(t *testing.T) {
	// The question a PSIRT is asked first when an advisory lands: where is
	// this in what we ship. The box said it searched issues and matched
	// component names alone, so it answered an empty list — which reads as
	// "we do not ship it" rather than as "that is not what this searches".
	//
	// Aliases count, because an issue is one thing under several names: the
	// name a reporter used has to reach the row filed under the name a
	// scanner used, or the answer depends on which feed arrived first.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		reported := found("CVE-2026-8899", libnl)
		reported.Issue.Aliases = []string{"GHSA-aaaa-bbbb-cccc"}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{reported, found("CVE-2026-7000", swss)}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PrivateRead)

		for _, term := range []string{"CVE-2026-8899", "cve-2026-8899", "GHSA-aaaa-bbbb-cccc", "8899"} {
			rows, _, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
				finding.Filter{Search: term})
			if err != nil {
				t.Fatalf("%s: %v", term, err)
			}
			if len(rows) != 1 {
				t.Errorf("searching %q found %d rows, want the one issue", term, len(rows))
			}
		}

		// The component half still works, and the two do not interfere.
		rows, _, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Search: "libnl"})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Errorf("searching a component name found %d rows, want 1", len(rows))
		}

		// And a term matching neither finds nothing, so the widening did not
		// turn the filter into a pass-through.
		none, _, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Search: "nothing-is-called-this"})
		if err != nil {
			t.Fatal(err)
		}
		if len(none) != 0 {
			t.Errorf("a term matching nothing found %d rows", len(none))
		}
	})
}

func TestARowNamesWhatPullsItInEvenWhereTheRouteUpIsUnknown(t *testing.T) {
	// The row said "nothing records what pulls this in" whenever the way down
	// could not be walked. Those are two different things: the finding records
	// its consumer either way, and what is missing is the route up to the
	// build rather than what sits directly above.
	//
	// It happens where the inventory describes a fragment it never attached —
	// something holds the component, and nothing holds that. Saying nothing
	// pulls it in is then false about the one part we do know, and it is the
	// part somebody judging the finding actually reads.
	each(t, func(t *testing.T, f *fixture) {
		stray := at("stray-fragment", "2.0")
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{swss, libnl, stray},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss},
				// stray holds libnl, and nothing holds stray.
				{Parent: stray, Child: libnl},
			},
		})
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-STRAY", libnl)}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PrivateRead)
		rows, _, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, row := range rows {
			if row.Vulnerability != "CVE-2026-STRAY" {
				continue
			}
			found = true
			if row.Parent != stray.Name {
				t.Errorf("the row names %q as what pulls it in, want %q", row.Parent, stray.Name)
			}
			// The owner stays empty, because that is the part genuinely not
			// known — claiming the build holds it would be the comfortable
			// sentence rather than the true one.
			if row.Owner != "" {
				t.Errorf("the row claims an owner of %q where the route up is unknown", row.Owner)
			}
		}
		if !found {
			t.Fatal("the finding is not in the list at all")
		}
	})
}

// A person's own record here, as against what a scanner reported.
//
// Its own question rather than a shade of another: a recorded flaw is the only
// kind a person may close by hand, and the screen that records one had no way
// to list what had been recorded before — so somebody filing one could not
// check whether it was already filed.
func TestNarrowingToWhatSomebodyRecordedHere(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.planner(t, access.PrivateTriage)
		if _, _, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary: "The management socket accepts a request nobody authenticated.",
		}); err != nil {
			t.Fatal(err)
		}

		// A recorded flaw is undisclosed until somebody says otherwise, so
		// the reader has to be one who may see it — and the triage line is
		// off, because the question is what exists rather than what is worth
		// an afternoon.
		all, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{BelowFloor: true})
		if err != nil {
			t.Fatal(err)
		}
		if total != 3 {
			t.Fatalf("the build holds %d things to decide, wanted the two scanned and the "+
				"one recorded", total)
		}
		kept, keptTotal, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Origin: finding.RecordedByHand, BelowFloor: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(kept) != 1 || keptTotal != 1 {
			t.Fatalf("asking for what was recorded kept %d rows and counted %d of %d",
				len(kept), keptTotal, len(all))
		}
		if kept[0].Component != swss.Name {
			t.Errorf("the recorded flaw came back as %q", kept[0].Component)
		}

		// And the other way, which a flag could not ask: the screen offered
		// "Scanner" and could only send the absence of "entered by hand", so
		// choosing it narrowed nothing while the panel showed it as chosen.
		scanned, scannedTotal, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Origin: finding.ReportedByAScanner, BelowFloor: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(scanned) != 2 || scannedTotal != 2 {
			t.Fatalf("asking for what a scanner reported kept %d rows and counted %d of %d",
				len(scanned), scannedTotal, len(all))
		}
		if len(scanned)+len(kept) != len(all) {
			t.Errorf("the two origins answer %d rows between them, out of %d",
				len(scanned)+len(kept), len(all))
		}
	})
}

func TestSeveralStatesAreAskedForTogether(t *testing.T) {
	// "Undecided or waiting on approval" is the working list of a triager who
	// wants everything not yet settled, and one value could not ask it. Each
	// state is a condition over the group's decision counts, so a set of them
	// is those conditions OR-ed rather than four conditions nothing satisfies
	// at once.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
			found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		count := func(t *testing.T, states ...string) int {
			t.Helper()
			_, total, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0,
				finding.Filter{States: states})
			if err != nil {
				t.Fatal(err)
			}
			return total
		}

		undecided := count(t, "undecided")
		if undecided != 2 {
			t.Fatalf("%d undecided, want both", undecided)
		}
		// A request for a state nothing is in adds nothing, and asking for it
		// beside one that matches keeps what that one matched — an OR, not an
		// AND.
		if both := count(t, "undecided", "agreed"); both != undecided {
			t.Errorf("undecided or agreed gave %d, want the %d that are undecided",
				both, undecided)
		}
		if agreed := count(t, "agreed"); agreed != 0 {
			t.Errorf("%d agreed, want none", agreed)
		}
		// And an empty set narrows nothing rather than everything, which is
		// what an unset control submitting a blank member would otherwise do.
		if none := count(t, ""); none != 2 {
			t.Errorf("an empty set kept %d, want everything", none)
		}
	})
}

// The list filters on the rating in force, and shows it.
//
// The floor and the deadline compare the rating of ours where somebody has
// made one, and the minimum-severity filter compared the published one — so a
// finding reassessed from low to critical had its urgency and its deadline
// moved and then disappeared from the list it was now at the top of, and drew
// the word that had been overruled.
func TestTheListFiltersOnTheRatingInForce(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		mild := found("CVE-2026-1", libnl)
		mild.Issue.Severity = "low"
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}

		// Rated critical by this product, which is what the floor and the
		// clock already read.
		f.rate(t, f.productID, "CVE-2026-1", "critical")

		who := f.holding(t, access.PublicRead)
		groups, _, err := f.store.Groups(ctx, who, f.scope, 50, 0,
			finding.Filter{MinSeverity: "high"})
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 {
			t.Fatalf("asking for high and above found %d groups, want the reassessed one",
				len(groups))
		}
		if groups[0].Severity != "critical" {
			t.Errorf("the row reads %q, want the rating in force", groups[0].Severity)
		}

		// And a word typed with capitals narrows rather than doing nothing.
		shouted, _, err := f.store.Groups(ctx, who, f.scope, 50, 0,
			finding.Filter{MinSeverity: "High"})
		if err != nil {
			t.Fatal(err)
		}
		if len(shouted) != len(groups) {
			t.Errorf("asking for \"High\" found %d groups and \"high\" found %d",
				len(shouted), len(groups))
		}
	})
}

func TestTheBundleAndComponentListsFilterOnTheirOwnProductsRating(t *testing.T) {
	// The rating is read through one expression and the product it is read for
	// is carried on the filter, set where the selection is resolved. These two
	// lists reach that expression through helpers of their own, so a chain
	// that lost the product would answer with the published word — silently,
	// and only on that list. The findings list has its own check above.
	//
	// Two products, rating it in opposite directions, because a join that
	// merely exists is not the thing at risk: the compiler catches a missing
	// one on all four engines, and what it cannot catch is one bound to the
	// wrong product. With only this product rating it, a swapped binding reads
	// as no rating and looks the same as a lost one.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		mild := found("CVE-2026-EVERY", libnl)
		mild.Issue.Severity = "medium"
		mild.FixState, mild.FixedIn = finding.FixedUpstream, "3.9.0"
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.inAnotherProduct(t, "other-product")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		// This product raises it past the line; the other drops it below.
		// Either binding read the other way round gives the wrong answer, and
		// they give opposite wrong answers.
		f.rate(t, f.productID, "CVE-2026-EVERY", "critical")
		f.rate(t, f.productOf(t, elsewhere), "CVE-2026-EVERY", "low")

		otherID := f.productOf(t, elsewhere)
		theirs := finding.Scope{ProductID: &otherID}
		who := f.holdingIn(t, []int64{f.productID, otherID}, access.PublicRead)
		high := finding.Filter{MinSeverity: "high"}

		found := func(scope finding.Scope) (int, int) {
			t.Helper()
			bundles, _, err := f.store.Bundles(ctx, who, scope, 50, 0, high)
			if err != nil {
				t.Fatal(err)
			}
			components, _, err := f.store.ComponentGroups(ctx, who, scope, 50, 0, high)
			if err != nil {
				t.Fatal(err)
			}
			return len(bundles), len(components)
		}

		if bundles, components := found(f.scope); bundles != 1 || components != 1 {
			t.Errorf("in the product that rated it critical the lists found %d bundles and %d "+
				"components, want one of each — they are reading the other product's rating "+
				"or none", bundles, components)
		}
		if bundles, components := found(theirs); bundles != 0 || components != 0 {
			t.Errorf("in the product that rated it low the lists found %d bundles and %d "+
				"components, want none — they are reading this product's rating", bundles,
				components)
		}
	})
}

// The filter that finds what is with its author, and the count the row draws
// it from, are one question.
//
// The filter had written its own condition without the product and without
// the version match, so it kept a group whose own sent-back count was zero:
// matched by a claim returned in a different product, or by one keyed on a
// version the place stopped holding. A reader asking for what is waiting on
// them got rows whose state column said nothing was.
func TestWhatIsWithItsAuthorIsTheSameQuestionTheRowAnswers(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", swss),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		issueID := f.issueID(t, "CVE-2026-1")
		place := finding.PlaceIdentity(swss.Name, "")

		sentBack := func(productID int64, version string) {
			t.Helper()
			if _, err := f.db.DB.NewDelete().Table("decision").
				Where("vulnerability_id = ?", issueID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			row := map[string]any{
				"claim_id":   claimBy(t, f.db, somebody.ID),
				"product_id": productID, "vulnerability_id": issueID,
				"place_identity": place, "visibility": "public",
				"state":          "proposed",
				"needs_approval": true, "stands_at_any_version": false, "proposed_by": somebody.ID,
				"proposed_at":                time.Now().UTC(),
				"component_upstream_version": version,
				"live_key":                   "the-live-key",
				"sent_back_at":               time.Now().UTC(),
			}
			if _, err := f.db.DB.NewInsert().Model(&row).
				TableExpr("\"decision\"").Exec(ctx); err != nil {
				t.Fatalf("record a claim sent back: %v", err)
			}
		}
		// Both halves of the answer, which have to agree.
		asked := func(because string, want int) {
			t.Helper()
			groups, kept, err := f.store.Groups(ctx, who, f.scope, 50, 0,
				finding.Filter{SentBack: true})
			if err != nil {
				t.Fatal(err)
			}
			if kept != want {
				t.Errorf("%s: the filter kept %d, want %d", because, kept, want)
			}
			all, _, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			drawn := 0
			for _, group := range all {
				if group.SentBack {
					drawn++
				}
			}
			if drawn != want {
				t.Errorf("%s: %d rows draw as with their author, want %d", because, drawn, want)
			}
			if len(groups) != want {
				t.Errorf("%s: %d rows came back, want %d", because, len(groups), want)
			}
		}

		sentBack(f.productID, swss.Version)
		asked("a claim sent back here, at the version shipping here", 1)
		sentBack(f.productID, "0.9.0")
		asked("a claim sent back about a version this place stopped holding", 0)
		elsewhere, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		sentBack(elsewhere.ID, swss.Version)
		asked("a claim sent back in another product", 0)
	})
}

func TestANarrowingThatCannotBeAppliedAnswersNothingRatherThanEverything(t *testing.T) {
	// "Assigned to me" from a subject that is nobody. A pipeline credential
	// and the deployment looking at itself both hold no party, so there is
	// nothing the phrase can name — and the narrowing was dropped, so the
	// caller was handed every finding while the panel went on showing the
	// filter as on. A filter that cannot be applied answers nothing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)

		all, total, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if total == 0 {
			t.Fatal("nothing is open, so this checked nothing")
		}

		// The same reader, holding a party, asking for theirs: nothing is
		// assigned, so nothing comes back. That is the shape the answer below
		// has to match.
		mine, mineTotal, err := f.store.Groups(ctx, who, f.scope, 50, 0,
			finding.Filter{Assigned: []string{"me"}, HeldBy: []int64{101}})
		if err != nil {
			t.Fatal(err)
		}
		if len(mine) != 0 || mineTotal != 0 {
			t.Fatalf("%d of %d came back as theirs with nothing assigned", len(mine), mineTotal)
		}

		// And from the deployment looking at itself, which holds no party —
		// so "mine" names nothing there and the answer is nothing.
		nobody := access.Everything("a pass over the estate")
		asked, askedTotal, err := f.store.Groups(ctx, nobody, f.scope, 50, 0,
			finding.Filter{Assigned: []string{"me"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(asked) != 0 || askedTotal != 0 {
			t.Errorf("asking for what a subject holding no party is dealing with answered "+
				"%d of %d — every finding there is", len(asked), len(all))
		}
	})
}
