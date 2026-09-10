package finding_test

import (
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

		// What it would catch, before anything is placed.
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
		placed, filled, err := f.store.ApplyRules(ctx, f.productID, 100)
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
		again, _, err := f.store.ApplyRules(ctx, f.productID, 100)
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
		placed, _, err := f.store.ApplyRules(ctx, f.productID, 100)
		if err != nil {
			t.Fatal(err)
		}
		if placed == 0 {
			t.Error("the rule placed nothing, so the fold disagreed with the sweep")
		}
	})
}
