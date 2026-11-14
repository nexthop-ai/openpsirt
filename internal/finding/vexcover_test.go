// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"fmt"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// recorded is one decision occurrence a case records at the occurrence of
// CVE-2026-1 beneath a consumer, approved, not applicable and live at the
// versions the occurrence holds unless it says otherwise.
type recorded struct {
	under      string
	outcome    string
	mitigation string
	state      string
	component  string
	consumer   string
	gone       bool
	visibility string
	elsewhere  bool
}

// decidedBeneath ships libnl beneath two consumers with CVE-2026-1 open at
// both, records what a case says at each, and returns the occurrences by
// consumer name.
func (f *fixture) decidedBeneath(t *testing.T, said []recorded) map[string]finding.Finding {
	t.Helper()
	ctx := t.Context()
	f.shipped(t, twoConsumers())
	f.foundOnLibnl(t)
	occurrences := f.occurrencesOf(t, "CVE-2026-1")
	by := f.somebodyElse(t)
	versions := map[string]string{swss.Name: swss.Version, teamd.Name: teamd.Version}
	var other int64
	for i, s := range said {
		at := occurrences[s.under]
		row := decisionRow{By: by, Issue: at.VulnerabilityID, Occurrence: at.OccurrenceIdentity,
			State: "approved", Visibility: s.visibility, Key: fmt.Sprintf("key-%d", i)}
		outcome := s.outcome
		if outcome == "" {
			outcome = finding.OutcomeNotApplicable
		}
		row.Decision = decisionSaying(t, f.db, by, outcome)
		if s.mitigation != "" {
			if _, err := f.db.DB.NewUpdate().TableExpr(`"decision"`).Set(`"mitigation" = ?`, s.mitigation).
				Where(`"id" = ?`, row.Decision).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if s.state != "" {
			row.State = s.state
		}
		component, consumer := libnl.Version, versions[s.under]
		if s.component != "" {
			component = s.component
		}
		if s.consumer != "" {
			consumer = s.consumer
		}
		row.Component, row.Consumer = &component, &consumer
		if s.gone {
			row.Key = ""
		}
		if s.elsewhere {
			if other == 0 {
				made, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "edge-router", "Edge")
				if err != nil {
					t.Fatal(err)
				}
				other = made.ID
			}
			row.Product = other
		}
		f.decision(t, row)
	}
	return occurrences
}

// The VEX document of a build reads its findings and decisions as sets and
// counts them in the application; an advisory counts the same in one
// statement (WhollyCovered). Over every way a decision can fail to cover an
// occurrence, both say the same about libnl in a build holding it beneath two
// consumers: whether it is covered, by what outcome, and which decision
// speaks.
func TestTheVEXDocumentCountsAGroupAsCoveredAsAnAdvisoryDoes(t *testing.T) {
	s, d := swss.Name, teamd.Name
	cases := []struct {
		name    string
		said    []recorded
		covered bool
		// hidden, closed and analyzed are the consumer whose occurrence is
		// undisclosed, closed, or a code finding before the document is read.
		hidden, closed, analyzed string
	}{
		{name: "nothing decided"},
		{name: "one occurrence of two", said: []recorded{{under: s}}},
		{name: "both occurrences", said: []recorded{{under: s}, {under: d}}, covered: true},
		{name: "one at another version of the library",
			said: []recorded{{under: s}, {under: d, component: libnlNew.Version}}},
		{name: "one at another version of its consumer",
			said: []recorded{{under: s}, {under: d, consumer: "9.9"}}},
		{name: "a wrong match at any version", covered: true, said: []recorded{
			{under: s, outcome: finding.OutcomeMismatched, component: libnlNew.Version, consumer: "9.9"},
			{under: d, outcome: finding.OutcomeMismatched}}},
		{name: "two outcomes", said: []recorded{{under: s}, {under: d, outcome: finding.OutcomeAlreadyFixed}}},
		{name: "one proposed", said: []recorded{{under: s}, {under: d, state: "proposed"}}},
		{name: "one no longer live", said: []recorded{{under: s}, {under: d, gone: true}}},
		{name: "one decision undisclosed", said: []recorded{{under: s}, {under: d, visibility: "private"}}},
		{name: "one in another product", said: []recorded{{under: s}, {under: d, elsewhere: true}}},
		{name: "two at one occurrence", covered: true, said: []recorded{{under: d}, {under: s}, {under: s}}},
		{name: "not fixed with nothing to do", covered: true, said: []recorded{
			{under: s, outcome: finding.OutcomeWontFix}, {under: d, outcome: finding.OutcomeWontFix}}},
		{name: "not fixed naming what to do", covered: true, said: []recorded{
			{under: s, outcome: finding.OutcomeWontFix, mitigation: "Turn it off."},
			{under: d, outcome: finding.OutcomeWontFix, mitigation: "Turn it off."}}},
		{name: "an affected decision beside", said: []recorded{
			{under: s}, {under: s, outcome: finding.OutcomeAffected}, {under: d}}},
		{name: "the other occurrence undisclosed", said: []recorded{{under: s}}, hidden: d, covered: true},
		{name: "the other occurrence closed", said: []recorded{{under: s}}, closed: d, covered: true},
		{name: "the other occurrence a code finding", said: []recorded{{under: s}}, analyzed: d, covered: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				ctx := t.Context()
				occurrences := f.decidedBeneath(t, tc.said)
				if tc.hidden != "" {
					if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).Set(`"visibility" = ?`, "private").
						Where(`"id" = ?`, occurrences[tc.hidden].ID).Exec(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if tc.analyzed != "" {
					if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).Set(`"kind" = ?`, kind.Analysis).
						Where(`"id" = ?`, occurrences[tc.analyzed].ID).Exec(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if tc.closed != "" {
					if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).Set(`"closed_at" = ?`, f.built).
						Where(`"id" = ?`, occurrences[tc.closed].ID).Exec(ctx); err != nil {
						t.Fatal(err)
					}
				}

				visible := []access.Visibility{access.Public}
				groups, _, err := finding.CoveredInBuild(ctx, f.db.DB, f.productID, f.build, visible, 100)
				if err != nil {
					t.Fatal(err)
				}
				kinds, kindArgs := kind.VEX.Where(`"f"."kind"`)
				var asked []struct {
					Component string `bun:"component"`
					finding.Covering
				}
				q := f.db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
					Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
					Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
					ColumnExpr(`"c"."name" AS "component"`).
					Where(`"f"."build_id" = ?`, f.build).
					Where(`"f"."visibility" IN (?)`, "public").
					Where(kinds, kindArgs...).
					GroupExpr(`"f"."vulnerability_id", "c"."name"`)
				if err := finding.WhollyCovered(q, f.productID, visible).
					Scan(ctx, &asked); err != nil {
					t.Fatal(err)
				}
				if len(groups) != len(asked) {
					t.Fatalf("the document states %d groups, the advisory's count %d: %+v against %+v",
						len(groups), len(asked), groups, asked)
				}
				if tc.covered != (len(groups) == 1) {
					t.Fatalf("covered reads %v, want %v", len(groups) == 1, tc.covered)
				}
				for i := range groups {
					if groups[i].Component != asked[i].Component || groups[i].Covering != asked[i].Covering {
						t.Errorf("the document states %+v, the advisory's count %+v", groups[i], asked[i])
					}
				}
			})
		})
	}
}

// A group the build holds is stated affected only where every open occurrence
// stands under a decision in force that the issue applies, and says the least
// and the greatest of their outcomes.
func TestAGroupIsAffectedOnlyWhereEveryOccurrenceSaysTheIssueApplies(t *testing.T) {
	s, d := swss.Name, teamd.Name
	cases := []struct {
		name            string
		said            []recorded
		least, greatest string
	}{
		{name: "one occurrence of two", said: []recorded{{under: s, outcome: finding.OutcomeAffected}}},
		{name: "beside a dismissal", said: []recorded{
			{under: s, outcome: finding.OutcomeAffected}, {under: d}}},
		{name: "both alike", said: []recorded{
			{under: s, outcome: finding.OutcomeAffected}, {under: d, outcome: finding.OutcomeAffected}},
			least: finding.OutcomeAffected, greatest: finding.OutcomeAffected},
		{name: "two ways", said: []recorded{
			{under: s, outcome: finding.OutcomePatchNeeded}, {under: d, outcome: finding.OutcomeAffected}},
			least: finding.OutcomeAffected, greatest: finding.OutcomePatchNeeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.decidedBeneath(t, tc.said)
				got, err := finding.AffectedInBuild(t.Context(), f.db.DB, f.productID, f.build,
					[]access.Visibility{access.Public}, 100)
				if err != nil {
					t.Fatal(err)
				}
				if tc.least == "" {
					if len(got) != 0 {
						t.Fatalf("stated affected: %+v", got)
					}
					return
				}
				if len(got) != 1 || got[0].Least != tc.least || got[0].Greatest != tc.greatest {
					t.Fatalf("stated %+v, want one group from %s to %s", got, tc.least, tc.greatest)
				}
			})
		})
	}
}

// An occurrence whose own decisions disagree is no statement about it, though
// every occurrence beneath its consumer is decided.
func TestAnOccurrenceWhoseDecisionsDisagreeIsNotStatedAlone(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.decidedBeneath(t, []recorded{{under: swss.Name}, {under: swss.Name, outcome: finding.OutcomeAlreadyFixed}})
		groups, placed, err := finding.CoveredInBuild(t.Context(), f.db.DB, f.productID, f.build,
			[]access.Visibility{access.Public}, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 0 || len(placed) != 0 {
			t.Fatalf("stated %+v about the build and %+v about an occurrence", groups, placed)
		}
	})
}

// The read stops one past the most it was asked for, so reaching the ceiling
// reads apart from landing on it.
func TestTheGroupsCoveredStopOnePastTheMost(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.decidedBeneath(t, []recorded{{under: swss.Name}, {under: teamd.Name}})
		ctx := t.Context()
		f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-2", libnl))
		occurrences := f.occurrencesOf(t, "CVE-2026-2")
		by := f.somebodyElse(t)
		for i, under := range []string{swss.Name, teamd.Name} {
			at := occurrences[under]
			component, consumer := libnl.Version, map[string]string{swss.Name: swss.Version, teamd.Name: teamd.Version}[under]
			f.decision(t, decisionRow{By: by, Issue: at.VulnerabilityID, Occurrence: at.OccurrenceIdentity,
				State: "approved", Component: &component, Consumer: &consumer, Key: fmt.Sprintf("second-%d", i)})
		}
		visible := []access.Visibility{access.Public}
		for most, want := range map[int]int{0: 1, 1: 2, 2: 2} {
			groups, _, err := finding.CoveredInBuild(ctx, f.db.DB, f.productID, f.build, visible, most)
			if err != nil {
				t.Fatal(err)
			}
			if len(groups) != want {
				t.Errorf("asked for at most %d, read %d groups, want %d", most, len(groups), want)
			}
		}
	})
}

// A statement about one occurrence names the component by its name and stated
// package identifier, so a reader applies it to every component the build
// holds under them. Beneath its consumer, each of them counts: libz at 1.0
// decided beneath cons-one is no statement while libz at 2.0, of the same name
// and no package identifier, sits undecided beside it.
func TestAnOccurrenceIsStatedOnlyWhereEveryComponentOfItsNameBeneathIsDecided(t *testing.T) {
	consOne, consTwo := at("cons-one", "1.0"), at("cons-two", "1.0")
	older := graph.Described{Name: "libz", Version: "1.0"}
	newer := graph.Described{Name: "libz", Version: "2.0"}
	for _, tc := range []struct {
		name string
		// decided is the versions of libz decided beneath cons-one.
		decided []string
		stated  int
	}{
		{name: "the other version undecided", decided: []string{"1.0"}},
		{name: "both versions decided", decided: []string{"1.0", "2.0"}, stated: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				ctx := t.Context()
				f.shipped(t, graph.Snapshot{
					Root:       root,
					Components: []graph.Described{consOne, consTwo, older, newer},
					Dependencies: []graph.Dependency{
						{Parent: root, Child: consOne},
						{Parent: root, Child: consTwo},
						{Parent: consOne, Child: older},
						{Parent: consOne, Child: newer},
						{Parent: consTwo, Child: older},
					},
				})
				f.applied(t, found("CVE-2026-1", older), found("CVE-2026-1", newer))
				var open []struct {
					Issue      int64  `bun:"vulnerability_id"`
					Occurrence string `bun:"occurrence_identity"`
					Version    string `bun:"version"`
					Consumer   string `bun:"consumer"`
				}
				if err := f.db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
					Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
					Join(`JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
					ColumnExpr(`"f"."vulnerability_id", "f"."occurrence_identity"`).
					ColumnExpr(`"c"."version" AS "version", "uc"."name" AS "consumer"`).
					Where(`"f"."build_id" = ?`, f.build).Where(`"f"."closed_at" IS NULL`).
					Scan(ctx, &open); err != nil {
					t.Fatal(err)
				}
				if len(open) != 3 {
					t.Fatalf("the build holds %d open occurrences, want 3: %+v", len(open), open)
				}
				by := f.somebodyElse(t)
				for i, version := range tc.decided {
					for _, row := range open {
						if row.Consumer != consOne.Name || row.Version != version {
							continue
						}
						component, consumer := version, consOne.Version
						f.decision(t, decisionRow{By: by, Issue: row.Issue, Occurrence: row.Occurrence,
							State: "approved", Component: &component, Consumer: &consumer,
							Key: fmt.Sprintf("libz-%d", i)})
					}
				}
				groups, placed, err := finding.CoveredInBuild(ctx, f.db.DB, f.productID, f.build,
					[]access.Visibility{access.Public}, 100)
				if err != nil {
					t.Fatal(err)
				}
				if len(groups) != 0 {
					t.Errorf("stated %+v about the whole build, where cons-two's libz is undecided", groups)
				}
				if len(placed) != tc.stated {
					t.Fatalf("stated %d occurrences, want %d: %+v", len(placed), tc.stated, placed)
				}
				for _, one := range placed {
					if one.Component != "libz" || one.Consumer != consOne.Name {
						t.Errorf("stated %+v, want libz inside %s", one, consOne.Name)
					}
				}
			})
		})
	}
}

// A version a producer states with spaces around it is the version a decision
// is keyed on, trimmed, on every engine: the VEX document and an advisory both
// state libnl, first described with spaces, covered by decisions keyed "3.7.0".
// A trailing space alone is the one MySQL and MariaDB ignore in an equality
// and PostgreSQL, SQLite and the application do not.
func TestAVersionStatedWithSpacesIsCoveredByItsDecisionOnEveryEngine(t *testing.T) {
	for name, version := range map[string]string{
		"trailing": libnl.Version + " ",
		"around":   " " + libnl.Version + " ",
	} {
		t.Run(name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				ctx := t.Context()
				spaced := libnl
				spaced.Version = version
				f.shipped(t, graph.Snapshot{
					Root:       root,
					Components: []graph.Described{swss, teamd, spaced},
					Dependencies: []graph.Dependency{
						{Parent: root, Child: swss}, {Parent: root, Child: teamd},
						{Parent: swss, Child: spaced}, {Parent: teamd, Child: spaced},
					},
				})
				f.decidedBeneath(t, []recorded{{under: swss.Name}, {under: teamd.Name}})

				visible := []access.Visibility{access.Public}
				groups, _, err := finding.CoveredInBuild(ctx, f.db.DB, f.productID, f.build, visible, 100)
				if err != nil {
					t.Fatal(err)
				}
				if len(groups) != 1 {
					t.Errorf("the document states %d groups, want libnl covered: %+v", len(groups), groups)
				}
				var asked []struct {
					Component string `bun:"component"`
					finding.Covering
				}
				q := f.db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
					Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
					Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
					ColumnExpr(`"c"."name" AS "component"`).
					Where(`"f"."build_id" = ?`, f.build).
					GroupExpr(`"f"."vulnerability_id", "c"."name"`)
				if err := finding.WhollyCovered(q, f.productID, visible).
					Scan(ctx, &asked); err != nil {
					t.Fatal(err)
				}
				if len(asked) != 1 {
					t.Errorf("an advisory counts %d groups covered, want libnl: %+v", len(asked), asked)
				}
			})
		})
	}
}
