// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Who holds a group, read with the list's first level, and the decided places
// counted beside it over the places that carry them.

// listedAs is each group one filter lists inside one product and across
// products, as the issue and its places, in the order the page holds them.
func (f *fixture) listedAs(t *testing.T, who access.Subject, filter finding.Filter) ([]string, []string) {
	t.Helper()
	said := func(groups []finding.Group) []string {
		out := make([]string, 0, len(groups))
		for _, group := range groups {
			out = append(out, fmt.Sprintf("%s at %d", group.Vulnerability, group.Places))
		}
		return out
	}
	here, _, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, filter)
	if err != nil {
		t.Fatal(err)
	}
	across, _, err := f.store.Anywhere(t.Context(), who, 50, 0, filter)
	if err != nil {
		t.Fatal(err)
	}
	return said(here), said(across)
}

func TestWhoHoldsAFoldIsAskedOfEveryHeldPlaceAndCountsEachPlaceOnce(t *testing.T) {
	// One issue at both packages of a fold and a second at one of them. Held
	// at one package only, the fold's issue is neither nobody's nor
	// somebody's; held at both by this reader it is theirs, at its two places
	// and not four; held at the second package by somebody numbered either
	// side of the reader it is somebody's and not theirs. Asked with a state
	// as well, the decided places stack beside the partial groups and the
	// answers do not move.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		lib := graph.Described{
			Purl: "pkg:deb/debian/libcurl4t64@8.5.0", Name: "libcurl4t64", Version: "8.5.0",
			UpstreamName: "curl", UpstreamVersion: "8.5.0",
		}
		tool := graph.Described{
			Purl: "pkg:deb/debian/curl@8.5.0", Name: "curl", Version: "8.5.0",
			UpstreamName: "curl", UpstreamVersion: "8.5.0",
		}
		f.shipped(t, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{lib, tool},
			Dependencies: []graph.Dependency{{Parent: root, Child: lib}, {Parent: root, Child: tool}},
		})
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-FOLD", lib), found("CVE-2026-FOLD", tool), found("CVE-2026-LIB", lib),
		}); err != nil {
			t.Fatal(err)
		}
		// The reader and two other people, numbered one below the reader and
		// one above, so neither end of who holds a group answers alone.
		below := &access.Party{Kind: access.APerson}
		reader := &access.Party{ID: 2_000_000_000, Kind: access.APerson}
		above := &access.Party{ID: 3_000_000_000, Kind: access.APerson}
		for _, party := range []*access.Party{below, reader, above} {
			if _, err := f.db.DB.NewInsert().Model(party).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		who := access.NewPerson(1, "someone", false,
			map[int64][]access.Role{f.productID: {access.PublicTriage}}, reader.ID)
		mine := who.Mine()
		if len(mine) != 1 || mine[0] != reader.ID || below.ID >= reader.ID {
			t.Fatalf("the reader is assignable as %v and the others are %d and %d,"+
				" and the fixture means one party between them", mine, below.ID, above.ID)
		}
		hold := func(component graph.Described, by int64) {
			t.Helper()
			if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
				Set("assigned_to = ?", by).
				Where("vulnerability_id = ?", f.issueID(t, "CVE-2026-FOLD")).
				Where("component_id = (SELECT id FROM \"component\" WHERE purl = ?)", component.Purl).
				Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		check := func(when string, want map[string][]string) {
			t.Helper()
			for _, state := range [][]finding.ClaimStanding{nil, {finding.StandingUndecided}} {
				for word, groups := range want {
					filter := finding.Filter{Assigned: []string{word}, States: state}
					here, across := f.listedAs(t, who, filter)
					if !slices.Equal(here, groups) || !slices.Equal(across, groups) {
						t.Errorf("%s, %q, states %v: %v in the product and %v across products, want %v",
							when, word, state, here, across, groups)
					}
				}
			}
		}

		hold(lib, mine[0])
		check("held at one package", map[string][]string{
			"nobody":   {"CVE-2026-LIB at 1"},
			"somebody": {},
			"me":       {},
		})
		hold(tool, mine[0])
		check("held at both packages by the reader", map[string][]string{
			"nobody":   {"CVE-2026-LIB at 1"},
			"somebody": {"CVE-2026-FOLD at 2"},
			"me":       {"CVE-2026-FOLD at 2"},
		})
		for _, other := range []*access.Party{below, above} {
			hold(tool, other.ID)
			check(fmt.Sprintf("held at the second package by party %d", other.ID), map[string][]string{
				"nobody":   {"CVE-2026-LIB at 1"},
				"somebody": {"CVE-2026-FOLD at 2"},
				"me":       {},
			})
		}
	})
}
