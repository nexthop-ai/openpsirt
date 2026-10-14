// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAFindingsHolderIsReadOffThePlacesItsReaderMayRead(t *testing.T) {
	// Who is dealing with a finding is one name where its places agree. A
	// place the reader may not read is not one of the places they are shown,
	// and a holder read off it names who is working undisclosed work.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 901, "someone")
		f.recorded(t, 902, "somebody-else")
		party := func(identity string) int64 {
			var id int64
			if err := f.db.DB.NewSelect().Table("person").Column("party_id").
				Where("identity = ?", identity).Scan(ctx, &id); err != nil {
				t.Fatal(err)
			}
			return id
		}
		open := f.open(t)
		if len(open) != 2 {
			t.Fatalf("the issue sits at %d places, want two", len(open))
		}
		for i, holder := range []string{"someone", "somebody-else"} {
			q := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
				Set("assigned_to = ?", party(holder)).Where("id = ?", open[i].ID)
			if i == 1 {
				q = q.Set("visibility = ?", access.Private)
			}
			if _, err := q.Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		who := f.holding(t, access.PublicTriage)
		evidence, err := f.store.Detail(ctx, who, f.target, open[0].VulnerabilityID, open[0].ComponentID)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.AssignedTo != "someone" {
			t.Errorf("a reader of the disclosed place reads its holder as %q", evidence.AssignedTo)
		}
	})
}

func TestAFindingsRoutingRuleIsReadOffThePlacesItsReaderMayRead(t *testing.T) {
	// The rule that placed a finding is one name where its places agree. A
	// rule read off a place the reader may not read names how undisclosed
	// work is routed.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if len(open) != 2 {
			t.Fatalf("the issue sits at %d places, want two", len(open))
		}
		planner := f.planner(t, access.PublicTriage, access.Assigner)
		where := f.team(t, "platform")
		for i, name := range []string{"in the open", "behind the embargo"} {
			rule, err := f.store.AddRule(ctx, planner, f.productID, where, name, name, "")
			if err != nil {
				t.Fatal(err)
			}
			q := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
				Set("routed_by = ?", rule.ID).Where("id = ?", open[i].ID)
			if i == 1 {
				q = q.Set("visibility = ?", access.Private)
			}
			if _, err := q.Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		who := f.holding(t, access.PublicTriage)
		evidence, err := f.store.Detail(ctx, who, f.target, open[0].VulnerabilityID, open[0].ComponentID)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.RoutedBy != "in the open" {
			t.Errorf("a reader of the disclosed place reads its rule as %q", evidence.RoutedBy)
		}
	})
}
