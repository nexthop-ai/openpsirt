// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// The state filter's decision table, counted beside the first level of the
// list and narrowed to the issues a filter needing a decision can reach, and
// the conditions over a group written as ranges.

// listed is the total one filter answers inside one product and across
// products, which the state filter builds in two different shapes.
func (f *fixture) listed(t *testing.T, who access.Subject, filter finding.Filter) (int, int) {
	t.Helper()
	_, here, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, filter)
	if err != nil {
		t.Fatal(err)
	}
	_, across, err := f.store.Anywhere(t.Context(), who, 50, 0, filter)
	if err != nil {
		t.Fatal(err)
	}
	return here, across
}

func TestAStateIsCountedOverOnlyThePlacesTheOtherConditionsKeep(t *testing.T) {
	// One issue at two places, agreed at one of them. Inside the container
	// holding the agreed place the issue is agreed; inside the other it is
	// undecided; over both it is partly decided, which is neither. A decision
	// counted at a place the other conditions dropped would answer the second
	// question with the first place's agreement.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		places := f.placesOf(t, "CVE-2026-1")
		if len(places) != 2 {
			t.Fatalf("the fixture put the issue at %d places, want 2", len(places))
		}
		f.decidedAt(t, f.somebodyElse(t), places[swss.Name], "approved", libnl.Version, swss.Version, "agreed")
		who := f.holding(t, access.PublicTriage)

		for _, asked := range []struct {
			under string
			state finding.ClaimStanding
			want  int
		}{
			{swss.Name, finding.StandingAgreed, 1},
			{swss.Name, finding.StandingUndecided, 0},
			{teamd.Name, finding.StandingAgreed, 0},
			{teamd.Name, finding.StandingUndecided, 1},
			{"", finding.StandingAgreed, 0},
			{"", finding.StandingUndecided, 0},
		} {
			here, across := f.listed(t, who, finding.Filter{
				Under: asked.under, States: []finding.ClaimStanding{asked.state},
			})
			if here != asked.want || across != asked.want {
				t.Errorf("%s under %q: %d in the product and %d across products, want %d",
					asked.state, asked.under, here, across, asked.want)
			}
		}
	})
}

func TestALapsedDecisionFiledUnderAMergedIssueFindsTheGroupOfTheIssueItMergedInto(t *testing.T) {
	// The issues a filter needing a decision can reach are read from the
	// decisions first. A decision filed under an issue that later merged into
	// the finding's is about the finding's issue, so the set names the issue
	// the merge kept, not the one the decision was filed under.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx, []finding.Named{
			{Identifier: "GHSA-aaaa-bbbb-cccc"},
		}); err != nil {
			t.Fatal(err)
		}
		kept, absorbed := f.issueID(t, "CVE-2026-1"), f.issueID(t, "GHSA-aaaa-bbbb-cccc")
		if _, err := f.db.DB.NewUpdate().TableExpr(`"vulnerability"`).
			Set("issue_id = ?", kept).Where("id = ?", absorbed).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		at := f.placesOf(t, "CVE-2026-1")[swss.Name]
		at.VulnerabilityID = absorbed
		f.decidedAt(t, f.somebodyElse(t), at, "lapsed", libnl.Version, swss.Version, "")

		here, across := f.listed(t, f.holding(t, access.PublicTriage),
			finding.Filter{States: []finding.ClaimStanding{finding.StandingLapsed}})
		if here != 1 || across != 1 {
			t.Errorf("a lapsed decision filed under the absorbed issue: %d lapsed in the product"+
				" and %d across products, want 1", here, across)
		}
	})
}

func TestSeveralStatesNeedingADecisionEachFindTheirOwnGroups(t *testing.T) {
	// Lapsed or waiting is the issues of lapsed decisions and the issues of
	// waiting ones together. Narrowed to either kind alone, the other's groups
	// drop out of a list that asked for them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl), found("CVE-2026-3", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		by := f.somebodyElse(t)
		f.decidedAt(t, by, f.placesOf(t, "CVE-2026-1")[swss.Name], "lapsed", libnl.Version, swss.Version, "")
		f.decidedAt(t, by, f.placesOf(t, "CVE-2026-2")[swss.Name], "proposed", libnl.Version, swss.Version, "waiting")
		who := f.holding(t, access.PublicTriage)

		for _, asked := range []struct {
			states []finding.ClaimStanding
			want   int
		}{
			{[]finding.ClaimStanding{finding.StandingLapsed, finding.StandingWaiting}, 2},
			{[]finding.ClaimStanding{finding.StandingWaiting, finding.StandingLapsed}, 2},
			{[]finding.ClaimStanding{finding.StandingLapsed, finding.StandingUndecided}, 2},
			{[]finding.ClaimStanding{finding.StandingAgreed}, 0},
		} {
			here, across := f.listed(t, who, finding.Filter{States: asked.states})
			if here != asked.want || across != asked.want {
				t.Errorf("%v: %d in the product and %d across products, want %d",
					asked.states, here, across, asked.want)
			}
		}
	})
}

func TestAStateOverSeveralBuildsCountsEachBuildsPlacesOnce(t *testing.T) {
	// One issue in two builds, agreed at the place both share, and one in the
	// first build alone and undecided. Over both builds the agreed issue is
	// one group of two places, both answered by the one decision. Asked
	// whether a group differs between builds, the first level is keyed on the
	// build as well, and the decided places beside it are counted per build.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, through(libnl))
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		f.decidedAt(t, f.somebodyElse(t), f.placesOf(t, "CVE-2026-1")[swss.Name],
			"approved", libnl.Version, swss.Version, "agreed")
		who := f.holding(t, access.PublicTriage)

		for _, asked := range []struct {
			state  finding.ClaimStanding
			want   string
			places int
		}{
			{finding.StandingAgreed, "CVE-2026-1", 2},
			{finding.StandingUndecided, "CVE-2026-2", 1},
		} {
			groups, total, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0,
				finding.Filter{States: []finding.ClaimStanding{asked.state}})
			if err != nil {
				t.Fatal(err)
			}
			if total != 1 || len(groups) != 1 || groups[0].Vulnerability != asked.want ||
				groups[0].Places != asked.places {
				t.Errorf("%s over both builds: %d groups %+v, want %s at %d places",
					asked.state, total, groups, asked.want, asked.places)
			}
		}

		// The agreed issue is in both builds, so it does not differ between
		// them, and the decided places counted per build must not make it.
		_, total, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0, finding.Filter{
			DiffersBetweenBuilds: true, States: []finding.ClaimStanding{finding.StandingAgreed},
		})
		if err != nil {
			t.Fatal(err)
		}
		if total != 0 {
			t.Errorf("agreed and differing between builds: %d groups, want none", total)
		}

		// CVE-2026-2 is in the first build only, so it differs between them;
		// agreed at its one place, it is the one group both conditions keep.
		// The total rather than the page, which one engine answers empty.
		f.decidedAt(t, f.somebodyElse(t), f.placesOf(t, "CVE-2026-2")[swss.Name],
			"approved", libnl.Version, swss.Version, "only-here")
		_, total, err = f.store.Groups(ctx, who, f.wholeProduct(), 50, 0, finding.Filter{
			DiffersBetweenBuilds: true, States: []finding.ClaimStanding{finding.StandingAgreed},
		})
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 {
			t.Errorf("agreed and in the first build alone: %d groups, want 1", total)
		}
	})
}

func TestAnOutcomeHoldsForAGroupOnlyWhereEveryPlaceIsAnsweredThatWay(t *testing.T) {
	// One issue at two places. Dismissed as not applicable at one of them, the
	// group is not a dismissal; dismissed at both, it is. Each place is counted
	// once, so two decided places compare equal to the group's two places.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		places := f.placesOf(t, "CVE-2026-1")
		if len(places) != 2 {
			t.Fatalf("the fixture put the issue at %d places, want 2", len(places))
		}
		who := f.holding(t, access.PublicTriage)
		dismissed := func(when string, want int) {
			t.Helper()
			here, across := f.listed(t, who, finding.Filter{Outcomes: []string{"not-applicable"}})
			if here != want || across != want {
				t.Errorf("%s: %d not applicable in the product and %d across products, want %d",
					when, here, across, want)
			}
		}
		by := f.somebodyElse(t)
		f.decidedAt(t, by, places[swss.Name], "approved", libnl.Version, swss.Version, "under-swss")
		dismissed("dismissed at one of two places", 0)
		f.decidedAt(t, by, places[teamd.Name], "approved", libnl.Version, teamd.Version, "under-teamd")
		dismissed("dismissed at both places", 1)
	})
}

func TestAGroupHalfHeldIsHeldNeitherByNobodyNorBySomebody(t *testing.T) {
	// "Nobody" is no place held and "somebody" is every place held, asked as
	// ranges over the count of held places. One of two places held is
	// neither, and the ranges must not reach it from either side.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		places := f.placesOf(t, "CVE-2026-1")
		party := &access.Party{Kind: access.APerson}
		if _, err := f.db.DB.NewInsert().Model(party).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		hold := func(at finding.Finding) {
			t.Helper()
			if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
				Set("assigned_to = ?", party.ID).Where("id = ?", at.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		who := f.holding(t, access.PublicTriage)
		held := func(when string, nobody, somebody int) {
			t.Helper()
			for word, want := range map[string]int{"nobody": nobody, "somebody": somebody} {
				here, across := f.listed(t, who, finding.Filter{Assigned: []string{word}})
				if here != want || across != want {
					t.Errorf("%s, %q: %d in the product and %d across products, want %d",
						when, word, here, across, want)
				}
			}
		}
		held("no place held", 1, 0)
		hold(places[swss.Name])
		held("one of two places held", 0, 0)
		hold(places[teamd.Name])
		held("both places held", 0, 1)
	})
}
