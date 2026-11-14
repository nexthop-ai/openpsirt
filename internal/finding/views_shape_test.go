// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// aView reads a page of fifty from one of the views beside the findings list,
// saying how many rows the page holds.
type aView func(ctx context.Context, store *finding.Store, who access.Subject, scope finding.Scope,
	filter finding.Filter) (int, error)

func componentsPage(ctx context.Context, store *finding.Store, who access.Subject, scope finding.Scope,
	filter finding.Filter) (int, error) {
	groups, _, err := store.ComponentGroups(ctx, who, scope, 50, 0, filter)
	return len(groups), err
}

func upgradesPage(ctx context.Context, store *finding.Store, who access.Subject, scope finding.Scope,
	filter finding.Filter) (int, error) {
	upgrades, _, err := store.PlannedUpgrades(ctx, who, scope, 50, 0, filter)
	return len(upgrades), err
}

// viewStatements is every statement a view sends for a page of fifty under
// the filter, over the across-products fixture.
func viewStatements(t *testing.T, db *database.DB, view aView, filter finding.Filter) []string {
	t.Helper()
	ctx := t.Context()
	f := declaredFixture(t, db)
	two := f.acrossProducts(t)
	who := f.holdingIn(t, []int64{two.first, two.second}, access.PublicRead, access.PrivateRead)

	seen := &statements{}
	f.hook(seen)
	held, err := view(ctx, f.store, who, f.scope, filter)
	if err != nil {
		t.Fatal(err)
	}
	if held == 0 {
		t.Fatal("the page holds no row, so it read nothing about its rows")
	}
	seen.mu.Lock()
	defer seen.mu.Unlock()
	return append([]string{}, seen.sent...)
}

// The components page reads where its rows could go and how their issues were
// rated in one statement. Each statement asking the list's kept groups under a
// decision filter builds the list's whole decision grouping over the build
// again, so the page holds two: its rows, and what it says about them.
//
// SQLite alone: the statements are the same on every engine.
func TestTheComponentsPageBuildsTheDecisionGroupingTwice(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		sent := viewStatements(t, db, componentsPage, finding.Filter{Planned: finding.NotPlanned})
		built := 0
		for _, statement := range sent {
			if strings.Contains(statement, `"decision_occurrence" AS "de"`) && strings.Contains(statement, `AS "f2"`) {
				built++
			}
		}
		if built != 2 {
			t.Errorf("the components page built the decision grouping %d times, want 2:\n%s",
				built, strings.Join(sent, "\n\n"))
		}
	})
}

// Under a filter that can pass with no decision, such as what no upgrade
// covers, the kept groups are joined to
// the view's rows through CROSS JOIN, which keeps the rows outermost on SQLite.
// Left to choose, SQLite walks every kept group and probes the findings once
// for each, which shows in a plan only once statistics hold a few thousand
// groups, so the statements are what is asserted.
//
// SQLite alone: the text is the same on every engine.
func TestTheKeptGroupsJoinAViewsRowsOutermost(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		sent := viewStatements(t, db, componentsPage, finding.Filter{Planned: finding.NotPlanned})
		joined := regexp.MustCompile(`(CROSS )?JOIN \(SELECT "f"\."vulnerability_id" AS "vulnerability_id", "c"\."fold_key" AS "fold"`)
		checked := 0
		for _, statement := range sent {
			for _, m := range joined.FindAllStringSubmatch(statement, -1) {
				checked++
				if m[1] == "" {
					t.Errorf("the kept groups are joined where SQLite may read them first:\n%s", statement)
				}
			}
		}
		if checked == 0 {
			t.Fatal("no statement joined the kept groups, so this checked nothing")
		}
	})
}

// A read about the rows of a page restricts its groups to the kept groups by
// membership under any filter reading the decision occurrences. PostgreSQL
// estimates the list's two-level groups at a twenty-fifth of what they hold,
// and joined to a page's finding rows it walks a large component's rows once
// per kept group, which shows only at scale, so the statements are what is
// asserted.
//
// SQLite alone: the text is the same on every engine.
func TestAReadAboutAPagesRowsKeepsGroupsByMembership(t *testing.T) {
	for _, one := range []struct {
		name, reads string
		view        aView
	}{
		// The components' upgrades and ratings, which alone read a rating.
		{"components", `"issue_rating" AS "ir"`, componentsPage},
		// An upgrade's package names, which alone name the branch.
		{"planned upgrades", `AS "branch_or_tag"`, upgradesPage},
	} {
		t.Run(one.name, func(t *testing.T) {
			dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
				sent := viewStatements(t, db, one.view, finding.Filter{Planned: finding.NotPlanned})
				checked := 0
				for _, statement := range sent {
					if !strings.Contains(statement, one.reads) {
						continue
					}
					checked++
					if !strings.Contains(statement, `("listed"."vulnerability_id", "ck"."fold_key") IN (`) {
						t.Errorf("a read about a page's rows joins the kept groups:\n%s", statement)
					}
				}
				if checked == 0 {
					t.Fatal("no statement read about the page's rows, so this checked nothing")
				}
			})
		})
	}
}
