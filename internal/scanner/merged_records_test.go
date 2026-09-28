// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// trailedByMerge says the administration trail holds this many rows of one
// kind, each written by a merge and naming no person.
func (f *runFixture) trailedByMerge(t *testing.T, kind trail.Kind, want int) {
	t.Helper()
	var rows []trail.Change
	if err := f.db.DB.NewSelect().Model(&rows).
		Where("ac.kind = ?", kind).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(rows) != want {
		t.Fatalf("the trail holds %d %s rows, want %d", len(rows), kind, want)
	}
	for _, row := range rows {
		if row.Actor != trail.ByMerge || row.By != nil || row.Became == nil ||
			!strings.HasPrefix(*row.Became, "Superseded when ") {
			t.Errorf("a %s row reads %+v, want one a merge wrote with its reason", kind, row)
		}
	}
}

// A third name, for an issue merged twice.
const otherAdvisory = "GHSA-dddd-eeee-ffff"

func TestADecisionMergedTwiceAppliesAtTheIssueThatStands(t *testing.T) {
	// Two advisories merge, and the issue they became later merges into the
	// national identifier. Every row read as the first merge's issue is read
	// as the one that stands, so a decision under either advisory still
	// answers its place.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		f.reporting(t, named(advisory, libnl), named(otherAdvisory, swss))
		proposer, approver := f.triagers(t)
		onLibnl := f.claims(t, proposer, approver, f.placeOf(t, proposer, advisory, "libnl-3-200"),
			triage.NotApplicable, true)
		onSwss := f.claims(t, proposer, approver, f.placeOf(t, proposer, otherAdvisory, "libswsscommon"),
			triage.NotApplicable, true)

		f.reporting(t, named(advisory, libnl), named(otherAdvisory, swss, advisory))
		f.reporting(t, named(advisory, libnl), named(otherAdvisory, swss), named(national, swss))
		f.reporting(t, named(national, libnl, advisory), named(national, swss))

		store := triage.NewStore(f.db.DB)
		for component, want := range map[string]int64{
			"libnl-3-200": onLibnl.ID, "libswsscommon": onSwss.ID,
		} {
			standing, err := store.Applying(ctx, f.placeOf(t, proposer, national, component))
			if err != nil {
				t.Fatal(err)
			}
			if standing == nil || standing.ID != want {
				t.Errorf("%s is answered by %+v after two merges, want decision %d",
					component, standing, want)
			}
		}
	})
}

func TestADecisionUnderAMergedNameIsReaffirmedAgainstTheRatingThatStands(t *testing.T) {
	// A dismissal agreed under the advisory name lapses when the product
	// rates the merged issue worse. Its proposer re-makes it at the place as
	// it reads now, and because the issue is worse than when it was agreed
	// to, it waits for a second person again.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		f.reporting(t, named(national, libnl), named(advisory, swss))
		proposer, approver := f.triagers(t)
		// Agreed at the published high, so only the product's critical is a
		// rise.
		decisions := triage.NewStore(f.db.DB)
		agreed, err := decisions.Propose(ctx, proposer, triage.Proposal{
			Place: f.placeOf(t, proposer, advisory, "libswsscommon"), Outcome: triage.WontFix,
			Reasoning: "Not worth fixing in this release.", By: proposer.ID,
			NeedsApproval: true, SeverityCenti: finding.SeverityScore("high"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decisions.ApproveClaim(ctx, approver, agreed.ClaimID, "", nil, ""); err != nil {
			t.Fatal(err)
		}

		f.reporting(t, named(national, libnl), named(advisory, swss, national))

		product, store, issues := f.rating(t)
		kept, err := issues.ByName(ctx, national)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Assess(ctx, approver, product, kept, "critical",
			"Reachable from any port the switch answers on."); err != nil {
			t.Fatal(err)
		}
		if _, err := decisions.LapseRatedWorse(ctx, triage.RatedWorseWhere{
			ProductID: product, Vulnerabilities: []int64{kept},
		}); err != nil {
			t.Fatal(err)
		}

		remade, err := decisions.Reaffirm(ctx, proposer, triage.Reaffirmation{
			PreviousID: agreed.ID,
			Place:      f.placeOf(t, proposer, national, "libswsscommon"),
			Reasoning:  "Still not worth fixing in this release.",
			By:         proposer.ID,
		})
		if err != nil {
			t.Fatalf("re-affirming a decision filed under the merged name: %v", err)
		}
		if remade.State != triage.Proposed {
			t.Errorf("re-affirmed over a worse rating, the decision is %s, want %s",
				remade.State, triage.Proposed)
		}
	})
}

func TestACaseGrantUnderAMergedNameReachesTheIssueItMergedInto(t *testing.T) {
	// Somebody brought into the case under the advisory name reaches what
	// they made under it, and the issue it merged into.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		f.reporting(t, named(national, libnl), named(advisory, swss))
		proposer, _ := f.triagers(t)
		issues := finding.NewVulnerabilities(f.db.DB)
		filed, err := issues.ByName(ctx, advisory)
		if err != nil {
			t.Fatal(err)
		}
		product, err := catalog.NewStore(f.db.DB).ProductByName(ctx, "sonic")
		if err != nil {
			t.Fatal(err)
		}
		rights := access.NewStore(f.db.DB)
		guest, err := rights.Ensure(ctx, "guest", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rights.AddToCase(ctx, product.ID, filed, guest.ID, proposer.ID); err != nil {
			t.Fatal(err)
		}

		f.reporting(t, named(national, libnl), named(advisory, swss, national))

		kept, err := issues.ByName(ctx, national)
		if err != nil {
			t.Fatal(err)
		}
		subject, err := rights.Resolve(ctx, "guest")
		if err != nil {
			t.Fatal(err)
		}
		for name, issue := range map[string]int64{"the merged name": filed, "the name that stands": kept} {
			if !subject.OnCase(product.ID, issue) {
				t.Errorf("the grant does not reach a record filed under %s", name)
			}
		}
	})
}
