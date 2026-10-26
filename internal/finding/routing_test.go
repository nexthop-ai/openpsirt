// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// team declares a team to route work to.
func (f *fixture) team(t *testing.T, name string) int64 {
	t.Helper()
	return f.teamReading(t, name, access.PublicRead, access.PrivateRead, access.InternalRead)
}

// teamReading declares a team whose one member holds these roles on the
// fixture's product, or a team of nobody where none is named.
func (f *fixture) teamReading(t *testing.T, name string, roles ...access.Role) int64 {
	t.Helper()
	ctx := t.Context()
	rights := access.NewStore(f.db.DB)
	one, err := rights.DeclareTeam(ctx, name, name)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) == 0 {
		return one.ID
	}
	member, err := rights.Ensure(ctx, name+"@example.com", name, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if err := rights.GrantRole(ctx, member.ID, f.productID, role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := rights.AddToTeam(ctx, one.ID, member.ID, member.ID); err != nil {
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

		rules, err := f.store.Rules(ctx, who, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 1 || rules[0].Beneath != "libnl-3-*" {
			t.Fatalf("the rules read back as %+v", rules)
		}
		// The precedence order is the product's triage configuration, read
		// by whoever triages there and nobody who only reads.
		if _, err := f.store.Rules(ctx, f.planner(t, access.PublicRead), f.productID); !errors.Is(
			err, access.ErrDenied) {
			t.Errorf("somebody who only reads the product read its rules: %v", err)
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
			Set(`"visibility" = ?`, string(access.Private)).
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

		private := f.planner(t, access.PublicTriage, access.PrivateTriage)
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
		f.applied(t, found("CVE-2026-CURL", lib), found("CVE-2026-CURL", tool))

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
		// Capitals change nothing about how much a key reaches. The rule is
		// matched folded, so its breadth is measured folded.
		if _, err := narrow.AddRule(ctx, who, f.productID, where, "shouted", "", "LIB*"); err == nil {
			t.Error("a rule naming most of the build in capitals was saved")
		} else if !errors.Is(err, finding.ErrTooBroad) {
			t.Errorf("a rule in capitals refused with %q", err)
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
		f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-2", teamd))
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

// flat is a build of the named libraries, each directly under the root, with
// one issue reported against each.
func (f *fixture) flat(t *testing.T, names ...string) {
	t.Helper()
	snap := graph.Snapshot{Root: root}
	var reported []finding.Reported
	for i, name := range names {
		library := at(name, "1.0")
		snap.Components = append(snap.Components, library)
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: root, Child: library})
		reported = append(reported, found(fmt.Sprintf("CVE-2026-%d", i+1), library))
	}
	f.shipped(t, snap)
	if _, err := f.store.Apply(t.Context(), f.target, f.run(t), reported); err != nil {
		t.Fatal(err)
	}
}

// The preview's total is how many components a rule matches, not how many it
// names: the names are a sample.
func TestAPreviewCountsEveryComponentItMatchesBeyondTheSample(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.flat(t, "libone", "libtwo", "libthree")
		who := f.planner(t, access.PublicTriage, access.Assigner)
		caught, err := f.store.WouldMatch(t.Context(), who, f.productID, "lib*", "", 1)
		if err != nil {
			t.Fatal(err)
		}
		if caught.Total != 3 || len(caught.Components) != 1 {
			t.Errorf("the preview says %d components and names %v, want 3 and a sample of 1",
				caught.Total, caught.Components)
		}
	})
}

// A rule's `*` is its only wildcard. The characters LIKE treats as wildcards
// appear in real package names and match themselves, on every engine.
func TestARulePatternMatchesUnderscoreAndPercentLiterally(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.flat(t, "lib_a", "libxa", "lib%b", "libyb")
		who := f.planner(t, access.PublicTriage, access.Assigner)
		for pattern, want := range map[string]string{"lib_*": "lib_a", "lib%*": "lib%b"} {
			caught, err := f.store.WouldMatch(t.Context(), who, f.productID, pattern, "", 20)
			if err != nil {
				t.Fatal(err)
			}
			if caught.Total != 1 || len(caught.Components) != 1 || caught.Components[0] != want {
				t.Errorf("%q matched %v, want only %s", pattern, caught.Components, want)
			}
		}
	})
}

// A batch is bounded across rules: a rule that fills it leaves nothing for the
// rules after it, and the sweep says it filled.
func TestARuleThatFillsTheBatchLeavesTheRulesAfterItForTheNextOne(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.flat(t, "libone", "libtwo")
		who := f.planner(t, access.PublicTriage, access.Assigner)
		where := f.team(t, "platform")
		for _, name := range []string{"libone", "libtwo"} {
			if _, err := f.store.AddRule(ctx, who, f.productID, where, name, name, ""); err != nil {
				t.Fatal(err)
			}
		}
		placed, filled, _, err := f.store.ApplyRules(ctx, f.productID, 1)
		if err != nil {
			t.Fatal(err)
		}
		if placed != 1 || !filled {
			t.Errorf("a batch of one placed %d and says filled %v, want 1 and true", placed, filled)
		}
		held := map[int64]bool{}
		for _, row := range f.open(t) {
			if row.AssignedTo != nil {
				held[row.ComponentID] = true
			}
		}
		if len(held) != 1 {
			t.Errorf("%d components are held after a batch of one, want the first rule's", len(held))
		}
	})
}

// A rule pointing at a retired team places nothing.
func TestARuleForARetiredTeamPlacesNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.flat(t, "libone")
		who := f.planner(t, access.PublicTriage, access.Assigner)
		where := f.team(t, "platform")
		if _, err := f.store.AddRule(ctx, who, f.productID, where, "libone", "libone", ""); err != nil {
			t.Fatal(err)
		}
		if err := access.NewStore(f.db.DB).RetireTeam(ctx, where); err != nil {
			t.Fatal(err)
		}
		placed, _, _, err := f.store.ApplyRules(ctx, f.productID, 100)
		if err != nil {
			t.Fatal(err)
		}
		if placed != 0 {
			t.Errorf("a rule for a retired team placed %d rows", placed)
		}
		for _, row := range f.open(t) {
			if row.AssignedTo != nil {
				t.Errorf("a row is held after the only rule's team retired: %+v", row)
			}
		}
	})
}

func TestARoutingRuleIsWrittenAndRetiredOnlyByAnAssigner(t *testing.T) {
	// A rule hands work to a team over and over with nobody present, which is
	// the act the assigner right names. Triaging the product is not it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		triager := f.planner(t, access.PublicTriage)
		where := f.team(t, "platform")
		if _, err := f.store.AddRule(ctx, triager, f.productID, where, "the library",
			"", "libnl-3-*"); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a triager without the assigner right wrote a rule: %v", err)
		}
		assigner := f.planner(t, access.PublicTriage, access.Assigner)
		rule, err := f.store.AddRule(ctx, assigner, f.productID, where, "the library", "", "libnl-3-*")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.RetireRule(ctx, triager, f.productID, rule.ID); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a triager without the assigner right retired a rule: %v", err)
		}
	})
}

// leadsAt turns two issues' rows into leads, one at each visibility a lead
// holds, and leaves the third as the vulnerability it was.
func leadsAt(t *testing.T, f *fixture) {
	t.Helper()
	ctx := t.Context()
	f.shipped(t, twoConsumers())
	if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
		found("CVE-2026-1", libnl), found("CVE-2026-2", libnl), found("CVE-2026-3", libnl),
	}); err != nil {
		t.Fatal(err)
	}
	for visibility, identifier := range map[access.Visibility]string{
		access.Internal: "CVE-2026-2", access.Private: "CVE-2026-1",
	} {
		if _, err := f.db.DB.NewUpdate().Table("finding").
			Set(`"kind" = ?`, "analysis").Set(`"visibility" = ?`, visibility).
			Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = ?)`, identifier).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// placedByRule applies the rules of the fixture's product and counts what they
// placed on its build, leads and the rest apart.
func placedByRule(t *testing.T, f *fixture) (leads map[access.Visibility]int, others int) {
	t.Helper()
	return placedWith(t, f, f.team(t, "platform"))
}

// placedWith is placedByRule with the rule pointing at the team named.
func placedWith(t *testing.T, f *fixture, team int64) (leads map[access.Visibility]int, others int) {
	t.Helper()
	ctx := t.Context()
	who := f.planner(t, access.PublicTriage, access.Assigner)
	if _, err := f.store.AddRule(ctx, who, f.productID, team, "the library",
		"", "libnl-3-*"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := f.store.ApplyRules(ctx, f.productID, 100); err != nil {
		t.Fatal(err)
	}
	var rows []finding.Finding
	if err := f.db.DB.NewSelect().Model(&rows).Where(`"f"."target_id" = ?`, f.target).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("the build holds no finding, so this checked nothing")
	}
	leads = map[access.Visibility]int{}
	for _, row := range rows {
		switch {
		case row.AssignedTo == nil:
		case row.Kind == "analysis":
			leads[row.Visibility]++
		default:
			others++
		}
	}
	return leads, others
}

// A lead is held and routed by the one implementation a finding is: a rule
// naming its component places it with the team, at whatever visibility it
// holds.
func TestARoutingRulePlacesTheLeadsNobodyHolds(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		leadsAt(t, f)
		leads, others := placedByRule(t, f)
		if others == 0 {
			t.Error("the rule placed no vulnerability")
		}
		for _, v := range []access.Visibility{access.Internal, access.Private} {
			if leads[v] == 0 {
				t.Errorf("the rule placed no lead at %s", v)
			}
		}
	})
}

// A lead every release of which is past its end of life is kept as it stands,
// so a rule places it nowhere, and places what is still in support.
func TestARoutingRulePlacesNoLeadPastItsEndOfLife(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		leadsAt(t, f)
		ended := time.Now().UTC().Add(-48 * time.Hour).Truncate(24 * time.Hour)
		if _, err := f.db.DB.NewUpdate().TableExpr(`"stream"`).Set(`"eol_on" = ?`, ended).
			Where(`"id" IN (SELECT "stream_id" FROM "target" WHERE "id" = ?)`, f.target).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		// The preview asks what the sweep asks: the vulnerability is the one
		// piece left to place.
		who := f.planner(t, access.PublicTriage, access.PrivateRead, access.InternalRead)
		caught, err := f.store.WouldMatch(t.Context(), who, f.productID, "", "libnl-3-*", 20)
		if err != nil {
			t.Fatal(err)
		}
		if caught.Work != 1 || caught.Unheld != 1 {
			t.Errorf("the preview counts %d pieces, %d unheld; want the vulnerability alone", caught.Work, caught.Unheld)
		}
		leads, others := placedByRule(t, f)
		if len(leads) != 0 {
			t.Errorf("the rule placed leads past their end of life: %v", leads)
		}
		if others == 0 {
			t.Error("the rule placed no vulnerability, so the release's end of life stopped all of it")
		}
	})
}

// What a rule would catch counts a lead as one piece of work, as it counts an
// issue at a component: two results of one rule in one component are two
// leads.
func TestARulePreviewCountsEachLeadItWouldPlace(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		leadsAt(t, f)
		leads, err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			ColumnExpr(`DISTINCT "vulnerability_id", "occurrence_identity"`).
			Where(`"kind" = ?`, "analysis").Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if leads < 2 {
			t.Fatalf("the fixture holds %d leads, so this checked nothing", leads)
		}
		who := f.planner(t, access.PublicTriage, access.PrivateRead, access.InternalRead)
		caught, err := f.store.WouldMatch(t.Context(), who, f.productID, "", "libnl-3-*", 20)
		if err != nil {
			t.Fatal(err)
		}
		if want := int(leads) + 1; caught.Work != want || caught.Unheld != want {
			t.Errorf("the preview counts %d pieces, %d unheld; want the vulnerability and each of %d leads",
				caught.Work, caught.Unheld, leads)
		}
	})
}

// A rule places work only at a visibility one member of its team reads, as a
// hand assignment to the team asks: what nobody on it reads stays with nobody.
func TestARoutingRulePlacesOnlyWhatOneMemberOfItsTeamReads(t *testing.T) {
	for _, c := range []struct {
		name   string
		roles  []access.Role
		leads  []access.Visibility
		others bool
	}{
		{"disclosed", []access.Role{access.PublicRead}, nil, true},
		{"internal", []access.Role{access.InternalRead}, []access.Visibility{access.Internal}, true},
		{"nobody", nil, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				leadsAt(t, f)
				leads, others := placedWith(t, f, f.teamReading(t, "desk", c.roles...))
				for _, v := range []access.Visibility{access.Internal, access.Private} {
					if want := slices.Contains(c.leads, v); (leads[v] > 0) != want {
						t.Errorf("the rule placed %d leads at %s; want them placed: %v", leads[v], v, want)
					}
				}
				if (others > 0) != c.others {
					t.Errorf("the rule placed %d vulnerabilities; want them placed: %v", others, c.others)
				}
			})
		})
	}
}

// A lead handed off as a flaw is closed work for its holder, so neither the
// sweep nor the preview counts it.
func TestARoutingRulePlacesNoHandedOffLead(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		leadsAt(t, f)
		who := f.planner(t, access.PublicTriage, access.PrivateRead, access.InternalRead)
		var lead finding.Finding
		if err := f.db.DB.NewSelect().Model(&lead).
			Where(`"f"."kind" = ?`, "analysis").Where(`"f"."visibility" = ?`, access.Internal).
			Limit(1).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		// A place of its own, as a lead's is: the fixture's leads share the
		// places of the vulnerabilities they were made from.
		lead.PlaceIdentity = "lead-handed-off"
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"occurrence_identity" = ?`, lead.PlaceIdentity).Where(`"id" = ?`, lead.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		person, err := access.NewStore(f.db.DB).Ensure(ctx, "hander@example.com", "Hander", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		before, err := f.store.WouldMatch(ctx, who, f.productID, "", "libnl-3-*", 20)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewInsert().Model(&finding.Handoff{
			ProductID: f.productID, PlaceIdentity: lead.PlaceIdentity, VulnerabilityID: lead.VulnerabilityID,
			Visibility: access.Internal, HandedBy: person.ID, HandedAt: time.Now().UTC().Truncate(time.Second),
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		after, err := f.store.WouldMatch(ctx, who, f.productID, "", "libnl-3-*", 20)
		if err != nil {
			t.Fatal(err)
		}
		if after.Work != before.Work-1 || after.Unheld != before.Unheld-1 {
			t.Errorf("the preview counts %d pieces, %d unheld, where it counted %d and %d before the hand-off",
				after.Work, after.Unheld, before.Work, before.Unheld)
		}
		leads, others := placedByRule(t, f)
		if leads[access.Private] == 0 || others == 0 {
			t.Errorf("the rule placed leads %v and %d vulnerabilities; want every piece but the handed-off lead",
				leads, others)
		}
		var placed finding.Finding
		if err := f.db.DB.NewSelect().Model(&placed).Where(`"f"."id" = ?`, lead.ID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if placed.AssignedTo != nil {
			t.Errorf("the handed-off lead was placed with party %d", *placed.AssignedTo)
		}
	})
}
