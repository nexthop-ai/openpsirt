package finding_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// team declares a team to route work to.
func (f *fixture) team(t *testing.T, name string) int64 {
	t.Helper()
	one, err := access.NewStore(f.db.DB).DeclareTeam(t.Context(), name, name)
	if err != nil {
		t.Fatal(err)
	}
	return one.ID
}

func TestARuleIsWrittenReadAndAppliedOnEveryEngine(t *testing.T) {
	// These had no store-level test at all: their only coverage was
	// handler tests, which run on two engines, so the SQL underneath — a
	// LIKE with an ESCAPE clause, and a write whose result is read back as
	// a row count to decide whether the batch filled — had never executed
	// on MySQL or MariaDB. The justification which tests run on which
	// engines gives is that the MySQL pair caught two bugs of exactly this
	// shape in one week.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		who := f.planner(t, access.PublicTriage, access.Assigner)
		where := f.team(t, "platform")

		// A glob, because the escape clause is the part with no portable
		// default: the character that escapes a wildcard is chosen by the
		// statement, and an engine that did not take the clause would treat
		// the marker as a literal and match nothing.
		rule, err := f.store.AddRule(ctx, who, f.productID, where, "kernel and friends",
			"", "libnl-3-*")
		if err != nil {
			t.Fatal(err)
		}
		if rule.Ordinal != 1 {
			t.Errorf("the first rule is ordinal %d, want the first place", rule.Ordinal)
		}

		rules, err := f.store.Rules(ctx, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 1 || rules[0].Beneath != "libnl-3-*" {
			t.Fatalf("the rules read back as %+v", rules)
		}

		// Its catch, before anything is placed.
		caught, err := f.store.WouldMatch(ctx, who, f.productID, "", "libnl-3-*", 20)
		if err != nil {
			t.Fatal(err)
		}
		if caught.Total != 1 || len(caught.Components) != 1 {
			t.Fatalf("the preview matched %d components (%v), want the one",
				caught.Total, caught.Components)
		}
		// One issue in one component, whatever it sits at — the unit the
		// findings list counts in, not the two places it sits at.
		if caught.Work != 1 || caught.Unheld != 1 {
			t.Errorf("the preview says %d pieces of work and %d unheld, want one of each",
				caught.Work, caught.Unheld)
		}

		// And applying it places exactly that.
		placed, filled, _, err := f.store.ApplyRules(ctx, f.productID, 100)
		if err != nil {
			t.Fatal(err)
		}
		if filled {
			t.Errorf("a batch of a hundred reports itself full on two rows")
		}
		if placed == 0 {
			t.Fatal("the rule placed nothing")
		}
		held := 0
		for _, row := range f.open(t) {
			if row.AssignedTo != nil {
				held++
			}
		}
		if held != placed {
			t.Errorf("%d rows were placed and %d are held", placed, held)
		}

		// Running it again places nothing: the rows are held, and a sweep
		// that kept re-placing held work would never come to an end.
		again, _, _, err := f.store.ApplyRules(ctx, f.productID, 100)
		if err != nil {
			t.Fatal(err)
		}
		if again != 0 {
			t.Errorf("a second sweep placed %d rows that were already held", again)
		}
	})
}

func TestAPreviewShowsOnlyWhatTheAskerMayRead(t *testing.T) {
	// visibility on the query and a role per product at the store rather
	// than at the handler. The preview answers counts and component names
	// over the rows a rule would catch, and it took no subject at all: a
	// public-only reader was told how many pieces of work sit at a
	// component and which components those are, over findings nobody has
	// announced.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		// Everything about this component is undisclosed.
		if _, err := f.db.DB.NewUpdate().Table("finding").
			Set("visibility = ?", string(access.Private)).
			Where("1 = 1").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		public := f.planner(t, access.PublicTriage)
		seen, err := f.store.WouldMatch(ctx, public, f.productID, "", "libnl-3-*", 20)
		if err != nil {
			t.Fatal(err)
		}
		if seen.Work != 0 || seen.Total != 0 || len(seen.Components) != 0 {
			t.Errorf("a public reader previewed %+v over undisclosed findings", seen)
		}

		private := f.planner(t, access.PrivateTriage)
		held, err := f.store.WouldMatch(ctx, private, f.productID, "", "libnl-3-*", 20)
		if err != nil {
			t.Fatal(err)
		}
		if held.Work != 1 {
			t.Errorf("somebody who may read undisclosed work previewed %+v", held)
		}
	})
}

func TestAComponentNamedOutsideASCIIMatchesTheSameOnEveryEngine(t *testing.T) {
	// Matching a component's name asked the engine to fold it, and the
	// four do not fold alike: SQLite's LOWER folds ASCII and nothing else
	// while the three servers fold the whole character set. So a component
	// named with any letter outside ASCII was swept by a routing rule on
	// three engines and not on the fourth, and which engine a deployment
	// ran decided the answer — with nothing reporting the difference,
	// because both look like a correct answer.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// A capital outside ASCII, which is the case the two folds disagree
		// about, in the place a rule looks: the component's own name.
		odd := at("libFÜNF", "1.0")
		f.shipped(t, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{swss, odd},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: swss, Child: odd}},
		})
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-2", odd)}); err != nil {
			t.Fatal(err)
		}

		who := f.planner(t, access.PublicTriage, access.Assigner)
		where := f.team(t, "platform")

		// The rule is typed in lower case, which is what somebody writes.
		if _, err := f.store.AddRule(ctx, who, f.productID, where, "the odd one",
			"", "libfünf"); err != nil {
			t.Fatal(err)
		}
		caught, err := f.store.WouldMatch(ctx, who, f.productID, "", "libfünf", 20)
		if err != nil {
			t.Fatal(err)
		}
		if caught.Total != 1 {
			t.Errorf("a rule spelled in lower case matched %d components named with a "+
				"capital outside ASCII, want the one", caught.Total)
		}
		placed, _, _, err := f.store.ApplyRules(ctx, f.productID, 100)
		if err != nil {
			t.Fatal(err)
		}
		if placed == 0 {
			t.Error("the rule placed nothing, so the fold disagreed with the sweep")
		}
	})
}

func TestWhatPlacedAFindingIsAnswerableAboutTheWholeFold(t *testing.T) {
	// The binary packages one source was built at one version are one thing to
	// a person, and the finding screen's rows are the whole fold — deliberately,
	// so that a form recording twelve places does not show six. Who holds it
	// and what placed it asked about one component instead, so the guarantee
	// those two state — one name for the whole group, empty where its places
	// disagree — was a guarantee about a group they could not see. A rule that
	// placed a third of a fold reported as no rule under one name and as the
	// whole thing under another.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// Two binaries of one source at one version, which is one fold.
		lib := graph.Described{
			Purl: "pkg:deb/debian/libcurl4t64@8.5.0", Name: "libcurl4t64", Version: "8.5.0",
			UpstreamName: "curl", UpstreamVersion: "8.5.0",
		}
		tool := graph.Described{
			Purl: "pkg:deb/debian/curl@8.5.0", Name: "curl", Version: "8.5.0",
			UpstreamName: "curl", UpstreamVersion: "8.5.0",
		}
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{lib, tool},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: lib}, {Parent: root, Child: tool},
			},
		})
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-CURL", lib), found("CVE-2026-CURL", tool),
		}); err != nil {
			t.Fatal(err)
		}

		who := f.planner(t, access.PublicTriage, access.Assigner)
		where := f.team(t, "platform")
		if _, err := f.store.AddRule(ctx, who, f.productID, where, "just the library",
			"", "libcurl4t64"); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := f.store.ApplyRules(ctx, f.productID, 100); err != nil {
			t.Fatal(err)
		}

		// Named either way, the screen says the same thing — and what it says
		// is that the fold does not agree.
		issue := f.issue(t, "CVE-2026-CURL")
		for _, named := range []string{"libcurl4t64", "curl"} {
			seen, err := f.store.Detail(ctx, who, f.target, issue, f.componentID(t, named))
			if err != nil {
				t.Fatalf("read the finding named %q: %v", named, err)
			}
			if seen.RoutedBy != "" {
				t.Errorf("named %q, the screen says %q placed the whole fold, and it placed "+
					"part of it", named, seen.RoutedBy)
			}
			if seen.AssignedTo != "" {
				t.Errorf("named %q, the screen says %q is dealing with the whole fold",
					named, seen.AssignedTo)
			}
		}
	})
}

func TestARuleNamingMostOfABuildIsRefused(t *testing.T) {
	// A rule says where in the tree something sits. A pattern matching most of
	// a build is not that: a bare glob matched every open node, and each was a
	// recursive walk of its own inside one request — from a route anybody who
	// may triage the product can reach, and from the sweep that re-runs a
	// saved rule on every pass.
	//
	// Refused rather than truncated, the way a rule matching nothing is
	// refused: a rule quietly applying to part of what it names is worse than
	// one nobody could save.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		who := f.planner(t, access.PublicTriage, access.Assigner)
		where := f.team(t, "platform")

		// The fixture is small, so the cap is brought down to it rather than
		// the tree being grown to the cap: what is being checked is the
		// refusal, and a fixture of two thousand components is a slow test
		// that says the same thing.
		narrow := finding.NewStoreReaching(f.db.DB, 1)
		if _, err := narrow.AddRule(ctx, who, f.productID, where, "everything", "", "*"); err == nil {
			t.Error("a rule naming most of the build was saved")
		} else if !errors.Is(err, finding.ErrTooBroad) {
			t.Errorf("refused with %q, which does not say what is wrong", err)
		}
		// And the preview says the same thing, so nobody is shown an answer
		// for a rule they cannot save.
		if _, err := narrow.WouldMatch(ctx, who, f.productID, "", "*", 20); err == nil {
			t.Error("a preview answered for a rule that cannot be saved")
		} else if !errors.Is(err, finding.ErrTooBroad) {
			t.Errorf("the preview refused with %q", err)
		}

		// A pattern naming a place is still a rule.
		if _, err := narrow.AddRule(ctx, who, f.productID, where, "the library",
			"", "libnl-3-200"); err != nil {
			t.Errorf("a rule naming one component was refused: %v", err)
		}
	})
}

func TestARuleThatOutgrewItsBoundDoesNotStopTheRestOfTheSweep(t *testing.T) {
	// A rule is refused when it is written, but the tree grows under one that
	// was accepted. That condition is permanent, so returned as a job failure
	// it stopped the product's whole routing — every rule ordered after it
	// included — and a retry could never clear it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", teamd),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.planner(t, access.PublicTriage, access.Assigner)
		where := f.team(t, "platform")

		// Saved while the bound still admits it, then applied by a store whose
		// bound is lower — which is the tree growing under it, without a
		// fixture of two thousand components to grow.
		if _, err := f.store.AddRule(ctx, who, f.productID, where, "everything",
			"", "*"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AddRule(ctx, who, f.productID, where, "the library",
			"", "libnl-3-200"); err != nil {
			t.Fatal(err)
		}

		narrow := finding.NewStoreReaching(f.db.DB, 1)
		placed, _, outgrown, err := narrow.ApplyRules(ctx, f.productID, 100)
		if err != nil {
			t.Fatalf("one outgrown rule failed the whole sweep: %v", err)
		}
		if len(outgrown) != 1 {
			t.Errorf("%d rules came back named as outgrown, wanted the one", len(outgrown))
		}
		// The rule ordered after it still ran, which is the whole point.
		if placed == 0 {
			t.Error("nothing was placed, so the rule behind the outgrown one never ran")
		}
	})
}
