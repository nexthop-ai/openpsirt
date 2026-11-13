// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"slices"
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
		who := f.someoneElse(t, access.PublicTriage)
		if _, err := f.store.CommitWithin(ctx, f.db.DB, who, f.productID,
			f.componentID(t, libnl.Name), "3.9.0", nil, nil,
			[]int64{f.build}, map[int64]string{}); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, withoutLibnl())
		f.applied(t)

		// The build's plan names the package it moved off as it stated it.
		planned, err := f.store.PlannedUpgradesFor(ctx, who, f.build)
		if err != nil {
			t.Fatal(err)
		}
		if len(planned) != 1 || !slices.Equal(planned[0].Components, []string{libnl.Name}) {
			t.Errorf("the plan for a package the build moved off names %v, want [%s] as the build"+
				" last stated it", planned, libnl.Name)
		}

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
		upgrades, _, err := f.store.PlannedUpgrades(ctx, f.holding(t, access.PublicRead), f.scope, 50, 0,
			finding.Filter{OpenOn: &between})
		if err != nil {
			t.Fatal(err)
		}
		if len(upgrades) != 1 || !slices.Equal(upgrades[0].Components, []string{libnl.Name}) {
			t.Errorf("the planned upgrades on a day the row was open name %v, want [%s] as the"+
				" build last stated it", upgrades, libnl.Name)
		}
	})
}

// A flaw recorded by the name its build stated is keyed on the component row's
// name, as a scan of that build keys it, so the two are one occurrence.
func TestAFlawEnteredByTheStatedNameIsKeyedAsAScanKeysIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		poisoned := libnl
		poisoned.Name = "nothing"
		f.shippedTo(t, elsewhere, through(poisoned))
		f.shipped(t, through(libnl))
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)

		rows, _, err := f.store.Enter(ctx, who, finding.Entering{
			BuildIDs: []int64{f.build}, Component: "LIBNL-3-200", Severity: "high",
			Summary: "The parser accepts a message it should refuse.",
		})
		if err != nil {
			t.Fatal(err)
		}
		if want := finding.OccurrenceIdentity("nothing", swss.Name); rows[0].OccurrenceIdentity != want {
			t.Error("a flaw entered by the build's own name is keyed on that name, where a scan keys the row's")
		}
	})
}

// Widening a recorded flaw to another build finds the component by the name
// the flaw's own build stated, never by the row's name, which another build
// may state for a different package.
func TestWideningAFlawFindsTheComponentByTheNameItsBuildStated(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		poisoned := libnl
		poisoned.Name = "nothing"
		f.shippedTo(t, elsewhere, through(poisoned))
		f.shipped(t, through(libnl))
		other := f.anotherVariant(t, "mellanox")
		decoy := at("nothing", "1.0")
		widened := through(libnl)
		widened.Components = append(widened.Components, decoy)
		widened.Dependencies = append(widened.Dependencies, graph.Dependency{Parent: root, Child: decoy})
		f.shippedTo(t, other, widened)
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)

		rows, _, err := f.store.Enter(ctx, who, finding.Entering{
			BuildIDs: []int64{f.build}, Component: libnl.Name, Severity: "high",
			Summary: "The parser accepts a message it should refuse.",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Affects(ctx, who, f.productID, rows[0].VulnerabilityID,
			[]int64{f.build, other}, ""); err != nil {
			t.Fatalf("widening: %v", err)
		}
		var added finding.Finding
		if err := f.db.DB.NewSelect().Model(&added).
			Where(`"vulnerability_id" = ?`, rows[0].VulnerabilityID).
			Where(`"build_id" = ?`, other).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if added.ComponentID != rows[0].ComponentID {
			t.Error("widening filed the flaw against the package the other build calls by the row's name")
		}
	})
}

// A component name typed into the findings list, its container filter and the
// trend asks one set of components of the finding, the row's name or a
// build's stated one: two sets joined by OR on the finding's column read every
// open finding the rest of the filter leaves.
func TestATypedComponentNameIsOneConditionOnTheFinding(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.applied(t, found("CVE-2026-1", libnl))
		who := f.holding(t, access.PublicRead)
		seen := &statements{}
		f.hook(seen)
		if _, _, err := f.store.Groups(ctx, who, f.scope, 50, 0,
			finding.Filter{Components: []string{libnl.Name}}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{Under: swss.Name}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Trend(ctx, who, f.scope, time.Now().Add(-time.Hour), time.Hour, 1,
			finding.Within{Component: libnl.Name}); err != nil {
			t.Fatal(err)
		}
		seen.mu.Lock()
		sent := append([]string{}, seen.sent...)
		seen.mu.Unlock()
		checked := 0
		for _, statement := range sent {
			if !strings.Contains(statement, `"c"."name_folded" = `) &&
				!strings.Contains(statement, `"c"."name_folded" IN (`) {
				continue
			}
			checked++
			for _, column := range []string{`"f"."component_id" IN (`, `"f"."consumer_id" IN (`} {
				if n := strings.Count(statement, column); n > 1 {
					t.Errorf("a typed component name asks %s %d times, joined by OR:\n%s", column, n, statement)
				}
			}
		}
		if checked < 3 {
			t.Fatalf("%d statements filtered by a typed component name, want the list's two and the trend's", checked)
		}
	})
}

// A rule's container is looked for by the component row's name and by the
// name the build stated in two reads, exact or a pattern: one condition across
// the two tables reads every open node of the deployment on MySQL.
func TestARulesContainerReadsTheRowsNameAndTheStatedNameApart(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.applied(t, found("CVE-2026-1", libnl))
		who := f.planner(t, access.PublicTriage)
		seen := &statements{}
		f.hook(seen)
		for _, beneath := range []string{swss.Name, "libswss*"} {
			caught, err := f.store.WouldMatch(ctx, who, f.productID, "", beneath, 20)
			if err != nil {
				t.Fatal(err)
			}
			if caught.Total == 0 {
				t.Errorf("a rule beneath %q catches nothing", beneath)
			}
		}
		seen.mu.Lock()
		sent := append([]string{}, seen.sent...)
		seen.mu.Unlock()
		checked := 0
		for _, statement := range sent {
			byRow := strings.Contains(statement, `"c"."name_folded" = `) ||
				strings.Contains(statement, `"c"."name_folded" LIKE `)
			byNode := strings.Contains(statement, `"n"."name_folded" = `) ||
				strings.Contains(statement, `"n"."name_folded" LIKE `)
			if byNode {
				checked++
			}
			if byRow && byNode {
				t.Errorf("a rule's container is asked of both names in one statement:\n%s", statement)
			}
		}
		if checked < 2 {
			t.Fatalf("%d statements read the stated name, want the exact name's and the pattern's", checked)
		}
	})
}
