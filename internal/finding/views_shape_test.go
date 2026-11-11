package finding_test

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// viewStatements is every statement the components page sends for a page of
// fifty under the filter, over the across-products fixture.
func viewStatements(t *testing.T, db *database.DB, filter finding.Filter) []string {
	t.Helper()
	ctx := t.Context()
	w, err := world.Declare(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		db: db, store: finding.NewStore(db.DB), graph: graph.NewStore(db.DB),
		build: w.Build.ID, productID: w.Product.ID, tag: w.Tag.ID, variant: w.Customer.ID,
		scans: ingest.NewStore(db.DB),
		scope: finding.Scope{
			ProductID: &w.Product.ID, BranchOrTagID: &w.Branch.ID, VariantID: &w.Customer.ID,
		},
		built: time.Now().UTC().Add(-72 * time.Hour),
	}
	two := f.acrossProducts(t)
	who := f.holdingIn(t, []int64{two.first, two.second}, access.PublicRead, access.PrivateRead)

	seen := &statements{}
	f.hook(seen)
	groups, _, err := f.store.ComponentGroups(ctx, who, f.scope, 50, 0, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) == 0 {
		t.Fatal("the components page holds no row, so it read nothing about its rows")
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
		sent := viewStatements(t, db, finding.Filter{Planned: finding.NotPlanned})
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
		sent := viewStatements(t, db, finding.Filter{Planned: finding.NotPlanned})
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
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		sent := viewStatements(t, db, finding.Filter{Planned: finding.NotPlanned})
		checked := 0
		for _, statement := range sent {
			if !strings.Contains(statement, `"issue_rating" AS "ir"`) {
				continue
			}
			checked++
			if !strings.Contains(statement, `("listed"."vulnerability_id", "ck"."fold_key") IN (`) {
				t.Errorf("a read about a page's rows joins the kept groups:\n%s", statement)
			}
		}
		if checked == 0 {
			t.Fatal("no statement read the ratings of a page's rows, so this checked nothing")
		}
	})
}
