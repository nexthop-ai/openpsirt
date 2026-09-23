// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"sort"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// The findings list is read in two statements — which groups, off an index,
// and then what is shown about them — and this pins that the split changed
// nothing about which groups a page holds, in what order, or how many there
// are: the page is what grouping the open rows in Go says it should be, under
// every kind of narrowing the list offers.
//
// The expectation is computed here from the raw open rows rather than read
// back from the store, so a grouping that quietly lost a filter or an
// ordering term would disagree with it rather than with itself.
func TestThePageIsTheGroupsInOrder(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		// Issues that rank differently, and some that rank the same, so the
		// order is decided by every term in turn: urgency, then how many
		// places, then the identifiers.
		reports := []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
			found("CVE-2026-3", swss), found("CVE-2026-4", teamd),
			found("CVE-2026-5", swss), found("CVE-2026-6", libnl),
		}
		reports[1].Issue.Severity = "critical"
		reports[2].Issue.Severity = "critical"
		reports[3].Issue.Severity = "low"
		reports[4].Issue.Exploited = true
		reports[5].Issue.Severity = "medium"
		reports[5].FixedIn = ""
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), reports); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		rows := f.open(t)
		type key struct{ issue, component int64 }
		type group struct {
			key
			places   int
			urgency  int64
			consumer map[int64]bool
			direct   bool
			fixed    bool
		}
		grouped := map[key]*group{}
		for _, row := range rows {
			k := key{row.VulnerabilityID, row.ComponentID}
			g := grouped[k]
			if g == nil {
				g = &group{key: k, consumer: map[int64]bool{}, fixed: true}
				grouped[k] = g
			}
			g.places++
			if row.Urgency > g.urgency {
				g.urgency = row.Urgency
			}
			if row.ConsumerID != nil {
				g.consumer[*row.ConsumerID] = true
			} else {
				g.direct = true
			}
			if row.FixedIn == "" {
				g.fixed = false
			}
		}
		names := map[int64]string{}
		var named []struct {
			ID   int64  `bun:"id"`
			Name string `bun:"name"`
		}
		if err := f.db.NewSelect().TableExpr("\"vulnerability\"").
			ColumnExpr("id, identifier AS \"name\"").Scan(t.Context(), &named); err != nil {
			t.Fatal(err)
		}
		for _, n := range named {
			names[n.ID] = n.Name
		}
		named = nil
		if err := f.db.NewSelect().TableExpr("\"component\"").
			ColumnExpr("id, name").Scan(t.Context(), &named); err != nil {
			t.Fatal(err)
		}
		components := map[int64]string{}
		for _, n := range named {
			components[n.ID] = n.Name
		}
		swssID, nowhere := int64(0), int64(0)
		for id, name := range components {
			if name == swss.Name {
				swssID = id
			}
		}

		expect := func(keep func(*group) bool) []string {
			var all []*group
			for _, g := range grouped {
				if keep(g) {
					all = append(all, g)
				}
			}
			sort.Slice(all, func(i, j int) bool {
				a, b := all[i], all[j]
				if a.urgency != b.urgency {
					return a.urgency > b.urgency
				}
				if a.places != b.places {
					return a.places > b.places
				}
				if a.issue != b.issue {
					return a.issue < b.issue
				}
				return a.component < b.component
			})
			out := make([]string, 0, len(all))
			for _, g := range all {
				out = append(out, names[g.issue]+" in "+components[g.component])
			}
			return out
		}
		read := func(groups []finding.Group) []string {
			out := make([]string, 0, len(groups))
			for _, g := range groups {
				out = append(out, g.Vulnerability+" in "+g.Component)
			}
			return out
		}
		same := func(a, b []string) bool {
			if len(a) != len(b) {
				return false
			}
			for i := range a {
				if a[i] != b[i] {
					return false
				}
			}
			return true
		}

		cases := []struct {
			name   string
			filter finding.Filter
			keep   func(*group) bool
		}{
			{"everything", finding.Filter{}, func(*group) bool { return true }},
			{"exploited", finding.Filter{Exploited: true},
				func(g *group) bool { return finding.Exploiting(g.urgency) }},
			{"with a fix", finding.Filter{HasFix: true}, func(g *group) bool { return g.fixed }},
			{"at least high", finding.Filter{MinSeverity: "high"},
				func(g *group) bool { return names[g.issue] != "CVE-2026-4" && names[g.issue] != "CVE-2026-6" }},
			{"one component", finding.Filter{Components: []string{libnl.Name}},
				func(g *group) bool { return components[g.component] == libnl.Name }},
			{"searched", finding.Filter{Search: "SWSS"},
				func(g *group) bool { return components[g.component] == swss.Name }},
			{"without one", finding.Filter{Exclude: []string{libnl.Name}},
				func(g *group) bool { return components[g.component] != libnl.Name }},
			{"one kind", finding.Filter{Ecosystems: []string{"deb"}}, func(*group) bool { return true }},
			{"another kind", finding.Filter{Ecosystems: []string{"golang"}}, func(*group) bool { return false }},
			{"inside one container", finding.Filter{Under: swss.Name},
				func(g *group) bool { return g.consumer[swssID] }},
			{"held by the build", finding.Filter{UnderTheBuild: true}, func(g *group) bool { return g.direct }},
			{"beneath nothing", finding.Filter{Beneath: &nowhere}, func(*group) bool { return false }},
			{"beneath one", finding.Filter{Beneath: &swssID},
				func(g *group) bool { return g.component == swssID || g.consumer[swssID] }},
			{"undecided", finding.Filter{States: []string{"undecided"}}, func(*group) bool { return true }},
			{"agreed", finding.Filter{States: []string{"agreed"}}, func(*group) bool { return false }},
		}
		for _, c := range cases {
			want := expect(c.keep)
			got, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, c.filter)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if !same(read(got), want) {
				t.Errorf("%s: page is\n  %v\nwanted\n  %v", c.name, read(got), want)
			}
			if total != len(want) {
				t.Errorf("%s: total %d, wanted %d", c.name, total, len(want))
			}
		}

		// Paged: two rows at a time walks the same order without a gap or a
		// repeat, and the total does not move with the page.
		want := expect(func(*group) bool { return true })
		var walked []string
		for offset := 0; offset < len(want); offset += 2 {
			got, total, err := f.store.Groups(t.Context(), who, f.scope, 2, offset, finding.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			if total != len(want) {
				t.Errorf("at offset %d the total is %d, wanted %d", offset, total, len(want))
			}
			walked = append(walked, read(got)...)
		}
		if !same(walked, want) {
			t.Errorf("paging walked\n  %v\nwanted\n  %v", walked, want)
		}

		// One step past the end. The total rides on the page's rows, and an
		// empty page has no row to carry it, so it is counted separately —
		// through the same filter, or a client stepping past the last page
		// sees the count fall to nothing and the pager with it. Under a plain
		// filter and under one that joins, because the count is the grouping
		// the page would have made, HAVING clauses included.
		for _, c := range []struct {
			name   string
			filter finding.Filter
		}{
			{"everything", finding.Filter{}},
			{"undecided", finding.Filter{States: []string{"undecided"}}},
		} {
			got, total, err := f.store.Groups(t.Context(), who, f.scope, 2, len(want), c.filter)
			if err != nil {
				t.Fatalf("%s past the end: %v", c.name, err)
			}
			if len(got) != 0 {
				t.Errorf("%s past the end: the page holds %d rows, want none", c.name, len(got))
			}
			if total != len(want) {
				t.Errorf("%s past the end: the total is %d, wanted %d", c.name, total, len(want))
			}
		}

		// The page's view of a row comes from the second statement,
		// keyed on the group. The counts have to be the same group's.
		got, _, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range got {
			for k, expected := range grouped {
				if names[k.issue] != g.Vulnerability || components[k.component] != g.Component {
					continue
				}
				if g.Places != expected.places || g.Urgency != expected.urgency {
					t.Errorf("%s in %s: %d places at urgency %d, wanted %d at %d",
						g.Vulnerability, g.Component, g.Places, g.Urgency, expected.places, expected.urgency)
				}
				if g.Exploited != finding.Exploiting(expected.urgency) {
					t.Errorf("%s in %s: exploited %v disagrees with its urgency", g.Vulnerability, g.Component, g.Exploited)
				}
				ways := len(expected.consumer)
				if expected.direct {
					ways++
				}
				if g.Chains != ways {
					t.Errorf("%s in %s: %d ways down, wanted %d", g.Vulnerability, g.Component, g.Chains, ways)
				}
			}
		}
	})
}

// A group holding one undisclosed place among any number of public ones is
// undisclosed.
//
// It was derived as a maximum of the visibility word, on the belief that
// "private" sorts after "public". It does not — 'r' comes before 'u' — so the
// expression answered "public" for exactly the mixed group it was written to
// catch, and the list drew no embargo marker on a row holding a finding
// nobody has announced. Somebody reads the row, sees nothing, and repeats it
// outside the deployment.
func TestOneUndisclosedPlaceMakesTheWholeGroupUndisclosed(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// One issue at a package two things pull in, so the fold holds two
		// places — and one of them is not disclosed.
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		var hidden int64
		if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			ColumnExpr("MIN(id)").Scan(ctx, &hidden); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("visibility = ?", access.Private).
			Where("id = ?", hidden).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PrivateTriage)
		groups, _, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 {
			t.Fatalf("the fold read as %d groups, want the one it is: %+v", len(groups), groups)
		}
		if !groups[0].Undisclosed {
			t.Error("a group holding an undisclosed place read as disclosed, so the list " +
				"would show no embargo marker on it")
		}
	})
}
