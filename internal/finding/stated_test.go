// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A component row is shared across products and holds what the first one
// stated. A finding shows the name and version its own build stated, so
// another product describing the package first decides nothing it shows.
func TestAFindingShowsTheNameAndVersionItsOwnBuildStated(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		cat := catalog.NewStore(f.db.DB)
		other, err := cat.DeclareProduct(ctx, "edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareVariant(ctx, other.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		poisoned := libnl
		poisoned.Name, poisoned.Version = "nothing", "99.0"
		f.shippedTo(t, f.anotherBranchOf(t, other.ID, "main"), graph.Snapshot{
			Root:         at("edge", "1.0"),
			Components:   []graph.Described{poisoned},
			Dependencies: []graph.Dependency{{Parent: at("edge", "1.0"), Child: poisoned}},
		})

		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if len(open) == 0 {
			t.Fatal("the issue opened nowhere")
		}
		who := f.holding(t, access.PublicRead)

		evidence, err := f.store.Detail(ctx, who, f.build, open[0].VulnerabilityID, open[0].ComponentID)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Component != libnl.Name || evidence.Version != libnl.Version {
			t.Errorf("a finding's evidence shows %s %s, which another product stated",
				evidence.Component, evidence.Version)
		}

		groups, _, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) == 0 {
			t.Fatal("the findings list holds nothing")
		}
		for _, group := range groups {
			if group.Component != libnl.Name || group.Version != libnl.Version {
				t.Errorf("the findings list shows %s %s, which another product stated",
					group.Component, group.Version)
			}
		}

		components, _, err := f.store.ComponentGroups(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		for _, group := range components {
			if group.Component != libnl.Name || group.Version != libnl.Version {
				t.Errorf("the list by component shows %s %s, which another product stated",
					group.Component, group.Version)
			}
		}

		// The versions carrying the issue are found by the build's own name for
		// the component, in any capitals, and by the row's.
		for _, typed := range []string{"LIBNL-3-200", "nothing"} {
			choices, err := f.store.VersionsWithIssue(ctx, who, f.build, open[0].VulnerabilityID, typed)
			if err != nil {
				t.Fatal(err)
			}
			if len(choices) != 1 || choices[0].Version != libnl.Version {
				t.Errorf("typed %q, the versions carrying the issue are %+v", typed, choices)
			}
		}

		rows, _, err := f.store.Register(ctx, who, f.build, finding.Registering{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatal("the register holds nothing")
		}
		for _, row := range rows {
			if row.Component != libnl.Name || row.Version != libnl.Version {
				t.Errorf("the register shows %s %s, which another product stated", row.Component, row.Version)
			}
		}
	})
}

// A page spanning products names each row as its own build stated it, or as
// the component row where that build states nothing: never as a build of
// another product stated it.
func TestARowAcrossProductsIsNeverNamedByAnotherProductsBuild(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.applied(t, found("CVE-2026-1", libnl))
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		theirs := twoConsumers()
		for i, c := range theirs.Components {
			if c.Purl == libnl.Purl {
				theirs.Components[i].Name, theirs.Components[i].Version = "nothing", "99.0"
			}
		}
		for i, d := range theirs.Dependencies {
			if d.Child.Purl == libnl.Purl {
				theirs.Dependencies[i].Child = theirs.Components[2]
			}
		}
		f.shippedTo(t, elsewhere, theirs)
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{found("CVE-2026-1", theirs.Components[2])}); err != nil {
			t.Fatal(err)
		}
		// The fixture's build as a node written before nodes held a name.
		if _, err := f.db.DB.NewUpdate().TableExpr(`"graph_node"`).
			Set(`"name" = NULL`).Set(`"version" = NULL`).Set(`"name_folded" = NULL`).
			Where(`"build_id" = ?`, f.build).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		who := f.holdingIn(t, []int64{f.productID, f.productOf(t, elsewhere)}, access.PublicRead)
		across, _, err := f.store.Anywhere(ctx, who, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		shown := map[string]bool{}
		for _, row := range across {
			shown[row.Component+" "+row.Version] = true
		}
		if !shown[libnl.Name+" "+libnl.Version] || !shown["nothing 99.0"] || len(shown) != 2 {
			t.Errorf("across products the rows show %v, want each product's own name", shown)
		}
	})
}

// A statement about a build names the component as that build stated it,
// whichever product described the package first.
func TestABuildsStatementNamesTheComponentAsTheBuildStatedIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		cat := catalog.NewStore(f.db.DB)
		other, err := cat.DeclareProduct(ctx, "edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareVariant(ctx, other.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		poisoned := libnl
		poisoned.Name = "nothing"
		f.shippedTo(t, f.anotherBranchOf(t, other.ID, "main"), graph.Snapshot{
			Root:         at("edge", "1.0"),
			Components:   []graph.Described{poisoned},
			Dependencies: []graph.Dependency{{Parent: at("edge", "1.0"), Child: poisoned}},
		})

		f.decidedBeneath(t, []recorded{{under: swss.Name}, {under: teamd.Name}})
		covered, _, err := finding.CoveredInBuild(ctx, f.db.DB, f.productID, f.build,
			[]access.Visibility{access.Public}, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(covered) != 1 || covered[0].Component != libnl.Name {
			t.Errorf("the build's statement names %+v, want %s", covered, libnl.Name)
		}
	})
}

// rot13 is a name no fold or substring of the original matches.
func rot13(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, name)
}

// The list and the trend show a component as its build stated it, so a name
// typed into any of their filters matches that name, though the component row
// holds the name another product stated first.
func TestANameTypedIntoAFilterMatchesTheNameTheBuildStated(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		f.shippedTo(t, elsewhere, stating(twoConsumers(), rot13))
		f.shipped(t, twoConsumers())
		f.applied(t, found("CVE-2026-1", libnl))
		who := f.holding(t, access.PublicRead)

		listed := func(filter finding.Filter) int {
			t.Helper()
			groups, _, err := f.store.Groups(ctx, who, f.scope, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			return len(groups)
		}
		for name, filter := range map[string]finding.Filter{
			"component": {Components: []string{strings.ToUpper(libnl.Name)}},
			"under":     {Under: swss.Name},
			"search":    {Search: "libnl"},
		} {
			if listed(filter) == 0 {
				t.Errorf("the %s filter, given the name the build stated, keeps nothing", name)
			}
		}
		if n := listed(finding.Filter{Exclude: []string{libnl.Name}}); n != 0 {
			t.Errorf("excluding the name the build stated keeps %d groups", n)
		}

		rows, _, err := f.store.Register(ctx, who, f.build, finding.Registering{Component: libnl.Name}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Errorf("the register's component filter, given the name the build stated, keeps nothing")
		}
		folds, err := finding.FoldsNamed(ctx, f.db.DB, []int64{f.build}, libnl.Name, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(folds) == 0 {
			t.Errorf("the name the build stated reaches nothing for the code-finding queue")
		}
		caught, err := f.store.WouldMatch(ctx, f.planner(t, access.PublicTriage), f.productID, "", libnl.Name, 20)
		if err != nil {
			t.Fatal(err)
		}
		if caught.Total == 0 {
			t.Errorf("a rule beneath the name the build stated catches nothing")
		}
		matches, err := f.store.Matching(ctx, who, f.wholeProduct(), "libnl", 20)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) == 0 {
			t.Errorf("the component chooser finds nothing under the name the build stated")
		}

		points, err := f.store.Trend(ctx, who, f.wholeProduct(), time.Time{}, 24*time.Hour, 2,
			finding.Within{Component: libnl.Name})
		if err != nil {
			t.Fatal(err)
		}
		if last := points[len(points)-1]; last.Open != 1 {
			t.Errorf("the trend of the component the build stated shows %d open, want 1", last.Open)
		}
	})
}

// A finding closed because its build no longer ships the component has no
// open node, and is shown by the name the build last stated, never the row's.
func TestAClosedRowIsShownByTheNameItsBuildLastStated(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		f.shippedTo(t, elsewhere, stating(twoConsumers(), rot13))
		f.shipped(t, twoConsumers())
		f.applied(t, found("CVE-2026-1", libnl))
		f.shipped(t, withoutLibnl())
		f.applied(t)

		rows, _, err := f.store.Register(ctx, f.holding(t, access.PublicRead), f.build,
			finding.Registering{Closed: true}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatal("the register holds no closed row")
		}
		for _, row := range rows {
			if row.Component != libnl.Name {
				t.Errorf("a closed row is shown as %q, want %q as the build last stated it",
					row.Component, libnl.Name)
			}
		}

		// And the list on a day it was open names it the same way.
		today := time.Now().UTC().Truncate(24 * time.Hour)
		if _, err := f.db.NewUpdate().Table("finding").Set(`"opened_at" = ?`, today.Add(-5*24*time.Hour)).
			Where(`"build_id" = ?`, f.build).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.NewUpdate().Table("finding").Set(`"closed_at" = ?`, today.Add(-3*24*time.Hour)).
			Where(`"build_id" = ?`, f.build).Where(`"closed_at" IS NOT NULL`).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		between := today.Add(-4 * 24 * time.Hour)
		groups, _, err := f.store.Groups(ctx, f.holding(t, access.PublicRead), f.scope, 50, 0,
			finding.Filter{OpenOn: &between})
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) == 0 {
			t.Fatal("the list on a day the row was open holds nothing")
		}
		for _, group := range groups {
			if group.Component != libnl.Name {
				t.Errorf("the list on a day the row was open shows it as %q, want %q as the build"+
					" last stated it", group.Component, libnl.Name)
			}
		}
	})
}
