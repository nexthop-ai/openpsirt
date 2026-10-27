// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// decidedSaying records a decision with one outcome at an occurrence.
func (f *fixture) decidedSaying(t *testing.T, by, issueID int64, occurrence, state, outcome, componentVersion, key string) {
	t.Helper()
	f.decision(t, decisionRow{
		By: by, Decision: decisionSaying(t, f.db, by, outcome), Issue: issueID, Occurrence: occurrence,
		State: state, Component: &componentVersion, Key: key,
	})
}

// The by-component view and the planned upgrades keep the groups the findings list
// keeps under a filter needing a decision: one issue at one fold, asked of the
// whole fold. A fold of two packages with the issue agreed at one of them is
// not agreed, so neither package carries it; an issue lapsed at one package of
// the fold is lapsed, and only that issue is carried there.
func TestTheViewsKeepTheListsGroupsUnderAFilterNeedingADecision(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		lib, tool := f.curlFold(t)
		// Another fold, carrying the issue lapsed in the first: it is kept
		// in the one fold and not in the other.
		zlib := graph.Described{
			Purl: "pkg:deb/debian/zlib1g@1.3", Name: "zlib1g", Version: "1.3",
			UpstreamName: "zlib", UpstreamVersion: "1.3",
		}
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{lib, tool, zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: lib}, {Parent: root, Child: tool}, {Parent: root, Child: zlib},
			},
		})
		fixed := func(id string, component graph.Described) finding.Reported {
			return finding.Reported{
				Issue:     finding.Named{Identifier: id, Severity: "high"},
				Component: component, FixState: finding.FixedUpstream, FixedIn: "8.6.0",
			}
		}
		// Applied as one run with the fold's own issue, so it stays open.
		f.applied(t,
			fixed("CVE-2026-CURL", lib), fixed("CVE-2026-CURL", tool),
			fixed("CVE-2026-LAPSED", lib), fixed("CVE-2026-LAPSED", zlib),
			fixed("CVE-2026-WAITING", tool),
			fixed("CVE-2026-PLANNED", tool),
			fixed("CVE-2026-OPEN", lib), fixed("CVE-2026-OPEN", tool),
		)
		at := func(component graph.Described) string { return finding.OccurrenceIdentity(component.Name, "") }
		somebody := f.somebodyElse(t)
		f.decided(t, somebody, f.issue(t, "CVE-2026-CURL"), at(lib), "approved", lib.Version, "curl-lib")
		f.decided(t, somebody, f.issue(t, "CVE-2026-LAPSED"), at(lib), "lapsed", lib.Version, "")
		f.decided(t, somebody, f.issue(t, "CVE-2026-WAITING"), at(tool), "proposed", tool.Version, "waiting")
		f.decidedSaying(t, somebody, f.issue(t, "CVE-2026-PLANNED"), at(tool), "approved",
			"upgrade-needed", tool.Version, "planned")
		who := f.holding(t, access.PublicTriage)

		// What each filter keeps: the issues each package carries, and how
		// many issues and occurrences the one bump to 8.6.0 closes.
		type kept struct {
			components          map[string]int
			issues, occurrences int
		}
		check := func(name string, filter finding.Filter, want kept) {
			t.Helper()
			groups, listed, err := f.store.Groups(ctx, who, f.scope, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if listed != want.issues {
				t.Fatalf("%s: the list holds %d groups %+v, and the fixture means %d", name, listed, groups, want.issues)
			}

			rows, total, err := f.store.ComponentGroups(ctx, who, f.scope, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]int{}
			for _, row := range rows {
				got[row.Component] = row.Issues
				sum := 0
				for _, n := range row.BySeverity {
					sum += n
				}
				if sum != row.Issues {
					t.Errorf("%s: %s is rated over %d issues and carries %d", name, row.Component, sum, row.Issues)
				}
				reached := 0
				for _, up := range row.Upgrades {
					reached = max(reached, up.Reached)
				}
				if reached != row.Issues {
					t.Errorf("%s: moving %s closes %d of its %d issues", name, row.Component, reached, row.Issues)
				}
			}
			if total != len(want.components) || len(got) != len(want.components) {
				t.Errorf("%s: by component %v (total %d), want %v", name, got, total, want.components)
			}
			for component, issues := range want.components {
				if got[component] != issues {
					t.Errorf("%s: %s carries %d issues, want %d", name, component, got[component], issues)
				}
			}
			alone, err := f.store.CountComponentGroups(ctx, who, f.scope, filter)
			if err != nil || alone != total {
				t.Errorf("%s: by component the total alone is %d (%v), and the page says %d", name, alone, err, total)
			}

			upgrades, bumps, err := f.store.PlannedUpgrades(ctx, who, f.scope, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if want.issues == 0 {
				if bumps != 0 || len(upgrades) != 0 {
					t.Errorf("%s: by upgrade %+v (total %d), want none", name, upgrades, bumps)
				}
			} else {
				if bumps != 1 || len(upgrades) != 1 {
					t.Fatalf("%s: by upgrade %+v (total %d), want the one bump", name, upgrades, bumps)
				}
				names := slices.Sorted(maps.Keys(want.components))
				if upgrades[0].Issues != want.issues || upgrades[0].Occurrences != want.occurrences ||
					!slices.Equal(upgrades[0].Components, names) {
					t.Errorf("%s: the bump closes %d issues at %d occurrences in %v, want %d at %d in %v", name,
						upgrades[0].Issues, upgrades[0].Occurrences, upgrades[0].Components, want.issues, want.occurrences, names)
				}
			}
			counted, err := f.store.CountPlannedUpgrades(ctx, who, f.scope, filter)
			if err != nil || counted != bumps {
				t.Errorf("%s: by upgrade the total alone is %d (%v), and the page says %d", name, counted, err, bumps)
			}
		}

		states := func(each ...finding.DecisionStanding) finding.Filter { return finding.Filter{States: each} }
		check("agreed", states(finding.StandingAgreed), kept{components: map[string]int{tool.Name: 1}, issues: 1, occurrences: 1})
		check("lapsed", states(finding.StandingLapsed), kept{components: map[string]int{lib.Name: 1}, issues: 1, occurrences: 1})
		check("waiting", states(finding.StandingWaiting), kept{components: map[string]int{tool.Name: 1}, issues: 1, occurrences: 1})
		check("lapsed or waiting", states(finding.StandingLapsed, finding.StandingWaiting),
			kept{components: map[string]int{lib.Name: 1, tool.Name: 1}, issues: 2, occurrences: 2})
		check("planned", finding.Filter{Planned: finding.PlannedOnly},
			kept{components: map[string]int{tool.Name: 1}, issues: 1, occurrences: 1})
		check("dismissed", finding.Filter{Outcomes: []string{"not-applicable"}}, kept{})
		check("lapsed and exploited", finding.Filter{States: []finding.DecisionStanding{finding.StandingLapsed},
			Exploited: true}, kept{})

		// Agreed at the fold's other package too, the fold's issue is agreed
		// and dismissed, at both packages.
		f.decided(t, somebody, f.issue(t, "CVE-2026-CURL"), at(tool), "approved", tool.Version, "curl-tool")
		check("agreed at both", states(finding.StandingAgreed),
			kept{components: map[string]int{lib.Name: 1, tool.Name: 2}, issues: 2, occurrences: 3})
		check("dismissed at both", finding.Filter{Outcomes: []string{"not-applicable"}},
			kept{components: map[string]int{lib.Name: 1, tool.Name: 1}, issues: 1, occurrences: 2})
	})
}
