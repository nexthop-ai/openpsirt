// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// acrossProducts is two products shipping the same components, carrying the
// same issues at the same place identities, with decisions in each that the
// other must not read as its own, and one finding in the second product that
// only a private reader sees.
type acrossProducts struct {
	first, second         int64
	firstName, secondName string
}

func (f *fixture) acrossProducts(t *testing.T) acrossProducts {
	t.Helper()
	ctx := t.Context()
	f.shipped(t, twoConsumers())
	if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
		found("CVE-2026-1", libnl), found("CVE-2026-2", swss), found("CVE-2026-3", libnl),
	}); err != nil {
		t.Fatal(err)
	}
	elsewhere := f.inAnotherProduct(t, "hedgehog")
	f.shippedTo(t, elsewhere, twoConsumers())
	if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere), []finding.Reported{
		found("CVE-2026-1", libnl), found("CVE-2026-2", swss), found("CVE-2026-3", libnl),
	}); err != nil {
		t.Fatal(err)
	}
	other := f.productOf(t, elsewhere)

	// Undisclosed in the second product only, so a reader holding that
	// product's disclosed findings alone is answered without it.
	if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
		Set("visibility = ?", access.Private).
		Where("target_id = ?", elsewhere).
		Where("vulnerability_id = ?", f.issueID(t, "CVE-2026-2")).
		Exec(ctx); err != nil {
		t.Fatal(err)
	}

	somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "somebody@example.com", "Them", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	underSwss := finding.PlaceIdentity(libnl.Name, swss.Name)
	underTeamd := finding.PlaceIdentity(libnl.Name, teamd.Name)
	decide := func(product int64, outcome, issue, place, componentVersion, consumerVersion, state, key string) {
		t.Helper()
		row := map[string]any{
			"claim_id":   claimSaying(t, f.db, somebody.ID, outcome),
			"product_id": product, "vulnerability_id": f.issueID(t, issue),
			"place_identity": place, "visibility": "public",
			"state": state, "needs_approval": true, "proposed_by": somebody.ID,
			"proposed_at":                time.Now().UTC(),
			"component_upstream_version": componentVersion,
			"consumer_upstream_version":  consumerVersion,
			"live_key":                   key,
		}
		if _, err := f.db.DB.NewInsert().Model(&row).TableExpr(`"decision"`).Exec(ctx); err != nil {
			t.Fatalf("record a %s claim: %v", state, err)
		}
	}
	// The first product agreed one place of CVE-2026-1 and promised an upgrade
	// over both places of CVE-2026-3. The second has a proposal waiting at the
	// very place the first agreed, which must not make the first's row waiting.
	decide(f.productID, "not-applicable", "CVE-2026-1", underSwss, libnl.Version, swss.Version, "approved", "a1")
	decide(f.productID, "upgrade-needed", "CVE-2026-3", underSwss, libnl.Version, swss.Version, "approved", "a3s")
	decide(f.productID, "upgrade-needed", "CVE-2026-3", underTeamd, libnl.Version, teamd.Version, "approved", "a3t")
	decide(other, "not-applicable", "CVE-2026-1", underSwss, libnl.Version, swss.Version, "proposed", "b1")
	// And dismissed CVE-2026-2 at its one place, which the second product
	// did not.
	decide(f.productID, "not-applicable", "CVE-2026-2", finding.PlaceIdentity(swss.Name, ""),
		swss.Version, "", "approved", "a2")
	return acrossProducts{first: f.productID, second: other, firstName: "sonic", secondName: "hedgehog"}
}

// rowsOf is a list as comparable text: the product, the issue, the component,
// how far it has been decided and how many places it covers.
func rowsOf(product string, groups []finding.Group) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		in := product
		if in == "" {
			in = g.Product
		}
		out = append(out, fmt.Sprintf("%s %s %s %s %d", in, g.Vulnerability, g.Component, g.State, g.Places))
	}
	sort.Strings(out)
	return out
}

// The list across products answers what each product's own list answers, for
// every filter that reads the decisions: the same rows, the same states and
// the same total, under the same visibility. The query spanning products
// correlates each decision with its own product rather than binding one, and
// the two spellings have to agree.
func TestTheListAcrossProductsAnswersWhatEachProductsListDoes(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		two := f.acrossProducts(t)

		readers := map[string]access.Subject{
			"reading both": f.holdingIn(t, []int64{two.first, two.second},
				access.PublicRead, access.PrivateRead),
			"reading the second's disclosed findings only": access.NewPerson(1, "someone", false,
				map[int64][]access.Role{
					two.first:  {access.PublicRead, access.PrivateRead},
					two.second: {access.PublicRead},
				}, 101),
		}
		filters := map[string]finding.Filter{
			"nothing":   {},
			"undecided": {States: []finding.ClaimStanding{finding.StandingUndecided}},
			"waiting":   {States: []finding.ClaimStanding{finding.StandingWaiting}},
			"agreed":    {States: []finding.ClaimStanding{finding.StandingAgreed}},
			"planned":   {Planned: finding.PlannedOnly},
			"unplanned": {Planned: finding.NotPlanned},
			"dismissed": {Outcomes: []string{"not-applicable"}},
			"the list's defaults": {
				Workable: finding.Working([]string{finding.OnBranch}, []string{finding.InSupport}),
				States:   []finding.ClaimStanding{finding.StandingUndecided},
				Assigned: []string{"nobody"},
				Planned:  finding.NotPlanned,
			},
		}
		names := map[int64]string{two.first: two.firstName, two.second: two.secondName}
		nonEmpty := map[string]bool{}
		for reader, who := range readers {
			for asked, filter := range filters {
				across, total, err := f.store.Anywhere(ctx, who, 50, 0, filter)
				if err != nil {
					t.Fatalf("%s, %s: %v", reader, asked, err)
				}
				var union []string
				unionTotal := 0
				for _, product := range []int64{two.first, two.second} {
					scope := finding.Scope{ProductID: &product}
					rows, n, err := f.store.Groups(ctx, who, scope, 50, 0, filter)
					if err != nil {
						t.Fatalf("%s, %s, in %s: %v", reader, asked, names[product], err)
					}
					union = append(union, rowsOf(names[product], rows)...)
					unionTotal += n
				}
				sort.Strings(union)
				got := rowsOf("", across)
				if total != unionTotal || strings.Join(got, "\n") != strings.Join(union, "\n") {
					t.Errorf("%s, %s: across products counted %d and answered\n  %s\neach product counted %d and answered\n  %s",
						reader, asked, total, strings.Join(got, "\n  "), unionTotal, strings.Join(union, "\n  "))
				}
				if len(got) > 0 {
					nonEmpty[asked] = true
				}
			}
		}
		// Each filter kept something for somebody, so no comparison above
		// passed by both sides answering nothing.
		for asked := range filters {
			if !nonEmpty[asked] {
				t.Errorf("%s answered nothing for every reader, so it compared nothing", asked)
			}
		}
	})
}

// statements records what a store sends, for a test that reads the plan of one.
type statements struct {
	mu   sync.Mutex
	sent []string
}

func (s *statements) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (s *statements) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, event.Query)
}

// The state filter across products reaches each open finding from a decision,
// through the finding's place index, as it does inside one product. Reached
// the other way, SQLite starts from every open finding and reads every
// decision of its product once per row, which is minutes on a real deployment
// and invisible on a fixture this size — so the plan is what is asserted.
//
// SQLite alone: the order asserted is the one SQLite takes without statistics,
// and the other engines choose theirs from statistics this fixture is too
// small to give.
func TestTheStateFilterAcrossProductsStartsFromTheDecisions(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w, err := world.Declare(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		f := &fixture{
			db: db, store: finding.NewStore(db.DB), graph: graph.NewStore(db.DB),
			target: w.Target.ID, productID: w.Product.ID, tag: w.Tag.ID, variant: w.Customer.ID,
			scans: ingest.NewStore(db.DB),
			scope: finding.Scope{
				ProductID: &w.Product.ID, StreamID: &w.Branch.ID, VariantID: &w.Customer.ID,
			},
			built: time.Now().UTC().Add(-72 * time.Hour),
		}
		two := f.acrossProducts(t)
		who := f.holdingIn(t, []int64{two.first, two.second}, access.PublicRead, access.PrivateRead)

		seen := &statements{}
		f.db.AddQueryHook(seen)
		if _, _, err := f.store.Anywhere(ctx, who, 50, 0, finding.Filter{
			States: []finding.ClaimStanding{finding.StandingUndecided},
		}); err != nil {
			t.Fatal(err)
		}
		seen.mu.Lock()
		sent := append([]string{}, seen.sent...)
		seen.mu.Unlock()

		checked := 0
		byPlace := regexp.MustCompile(`SEARCH f2 USING (COVERING )?INDEX finding_place_idx`)
		for _, statement := range sent {
			if !strings.Contains(statement, `AS "dd"`) {
				continue
			}
			checked++
			var plan []struct {
				ID     int    `bun:"id"`
				Parent int    `bun:"parent"`
				Unused int    `bun:"notused"`
				Detail string `bun:"detail"`
			}
			if err := f.db.DB.NewRaw("EXPLAIN QUERY PLAN "+statement).Scan(ctx, &plan); err != nil {
				t.Fatalf("explain a statement: %v", err)
			}
			var lines []string
			reached := false
			for _, step := range plan {
				lines = append(lines, step.Detail)
				reached = reached || byPlace.MatchString(step.Detail)
			}
			if !reached {
				t.Errorf("the state filter does not reach the findings from the decisions:\n  %s",
					strings.Join(lines, "\n  "))
			}
		}
		if checked == 0 {
			t.Fatal("no statement carried the state filter, so this checked nothing")
		}
	})
}
