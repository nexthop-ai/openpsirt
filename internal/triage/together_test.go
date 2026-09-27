// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestABulkClaimRecordsTheRatingInForceAsItsBaseline(t *testing.T) {
	// The baseline is what a re-affirmation compares today's rating against,
	// so it has to be the rating in force here rather than what was published.
	// Stored as the published score, a product that had assessed an issue down
	// held a baseline nobody was working to: the issue could be re-rated
	// critical here and the comparison would still read "no worse than when it
	// was agreed to", and the dismissal would carry with nobody else reading
	// it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// Published at 9.8, which is what the column holds.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Vulnerability)(nil)).
			Set("score_centi = ?", 980).Set("severity = ?", "critical").
			Where("id = ?", f.issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		// Assessed as medium here.
		rated := &finding.IssueRating{
			VulnerabilityID: f.issue, ProductID: f.product, Severity: "medium",
		}
		if _, err := f.db.DB.NewInsert().Model(rated).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		in := f.build(t, f.product, "2026.03")
		libfoo := f.component(t, "libfoo", "1.2.3")
		f.finds(t, in, libfoo, "place-of-libfoo", access.Public)

		_, recorded, _, err := f.store.Together(ctx, f.triager, triage.TogetherAt{
			TargetID: in.target, ComponentID: libfoo, VulnerabilityIDs: []int64{f.issue},
		}, triage.Proposal{
			Outcome: triage.NotApplicable, Justification: triage.CodeNotInExecutePath,
			Reasoning: "The parser is never reached: we only call the encoder.",
			By:        f.proposer, NeedsApproval: true,
		}, triage.DefaultBounds())
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) != 1 {
			t.Fatalf("%d decisions recorded, want the one place", len(recorded))
		}

		var written triage.Decision
		if err := f.db.DB.NewSelect().Model(&written).
			Where("id = ?", recorded[0]).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		want := finding.SeverityScore("medium")
		if written.SeverityCenti == nil || *written.SeverityCenti != want {
			t.Errorf("the baseline reads as %v, want %d — the rating in force here, "+
				"not the published score", written.SeverityCenti, want)
		}
	})
}

func TestABulkClaimNamesTheDecisionThatBlockedIt(t *testing.T) {
	// One live claim per combination of code holds here as it does anywhere,
	// so a selection covering something already decided is refused whole.
	// "Something in this selection is already decided" tells somebody holding
	// five hundred rows nothing they can act on, while the single-finding path
	// names the decision to go and revise. One spelling, and it names which.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.build(t, f.product, "2026.03")
		libfoo := f.component(t, "libfoo", "1.2.3")
		f.finds(t, in, libfoo, "place-of-libfoo", access.Public)

		at := triage.TogetherAt{
			TargetID: in.target, ComponentID: libfoo, VulnerabilityIDs: []int64{f.issue},
		}
		claim := triage.Proposal{
			Outcome: triage.NotApplicable, Justification: triage.CodeNotInExecutePath,
			Reasoning: "The parser is never reached: we only call the encoder.",
			By:        f.proposer, NeedsApproval: true,
		}
		_, recorded, _, err := f.store.Together(ctx, f.triager, at, claim, triage.DefaultBounds())
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) != 1 {
			t.Fatalf("%d decisions recorded, want the one place", len(recorded))
		}

		// The same selection again, which now collides with what it wrote.
		_, _, _, err = f.store.Together(ctx, f.triager, at, claim, triage.DefaultBounds())
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("a second claim was recorded over the first: %v", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprint(recorded[0])) {
			t.Errorf("the refusal does not name the decision that stands: %v", err)
		}
	})
}

func TestABulkClaimAskedToSkipLeavesOutWhatIsDecidedAndNamesIt(t *testing.T) {
	// Skipping is something the claimant asks for, and what it left out is
	// said: a claim covering less than was selected is one the claimant can
	// see is smaller, and the decision standing at each skipped place is where
	// they go next.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		both := f.twoIssues(t)
		first := both
		first.VulnerabilityIDs = both.VulnerabilityIDs[:1]
		_, standing, _, err := f.store.Together(ctx, f.triager, first, f.wontFix(),
			triage.DefaultBounds())
		if err != nil {
			t.Fatal(err)
		}

		// Unasked, the selection is refused whole.
		if _, _, _, err := f.store.Together(ctx, f.triager, both, f.wontFix(),
			triage.DefaultBounds()); !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("a selection covering a decided place was not refused: %v", err)
		}

		both.SkipDecided = true
		_, recorded, skipped, err := f.store.Together(ctx, f.triager, both,
			f.wontFix(), triage.DefaultBounds())
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) != 1 {
			t.Errorf("%d decisions recorded, want the one undecided place", len(recorded))
		}
		if len(skipped) != 1 || skipped[0].DecisionID != standing[0] ||
			skipped[0].VulnerabilityID != both.VulnerabilityIDs[0] {
			t.Errorf("what was skipped reads %+v, want decision %d on the first issue",
				skipped, standing[0])
		}

		// Everything decided now: nothing to claim, and nothing written.
		if _, _, _, err := f.store.Together(ctx, f.triager, both, f.wontFix(),
			triage.DefaultBounds()); !errors.Is(err, triage.ErrAllDecided) {
			t.Errorf("a selection that is all decided answered %v", err)
		}
	})
}

func TestABulkClaimsCapCountsWhatItWritesAfterSkipping(t *testing.T) {
	// The bound is on rows written. A place skipped is not written, so a
	// selection that would pass the cap once its decided places are left out
	// is not refused for them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		both := f.twoIssues(t)
		first := both
		first.VulnerabilityIDs = both.VulnerabilityIDs[:1]
		one := triage.Bounds{Review: 1, Places: 1}
		if _, _, _, err := f.store.Together(ctx, f.triager, first, f.wontFix(), one); err != nil {
			t.Fatal(err)
		}
		both.SkipDecided = true
		if _, recorded, _, err := f.store.Together(ctx, f.triager, both,
			f.wontFix(), one); err != nil || len(recorded) != 1 {
			t.Errorf("a claim writing one place under a cap of one answered %v, %d written",
				err, len(recorded))
		}
	})
}

func TestTheIssueLimitIsTheReviewersWhereAnythingGoesToASecondPerson(t *testing.T) {
	// Re-confirming what was already agreed to asks nobody to read anything
	// new, so it takes the larger limit; anything that goes back to an
	// approver takes the reviewer's. The place ceiling holds either way.
	b := triage.Bounds{Review: 2, Agreed: 5, Places: 10}
	for _, each := range []struct {
		issues, places  int
		review, refused bool
	}{
		{2, 10, true, false},
		{3, 3, true, true},
		{5, 5, false, false},
		{6, 6, false, true},
		{1, 11, false, true},
		{1, 11, true, true},
	} {
		err := b.Counted(each.issues, each.places, each.review)
		if (err != nil) != each.refused {
			t.Errorf("%d issues at %d places, review %v: refused %v, want %v (%v)",
				each.issues, each.places, each.review, err != nil, each.refused, err)
		}
	}
	// Unset is the shipped limits, never unbounded.
	if err := (triage.Bounds{}).Counted(1, 50001, false); err == nil {
		t.Error("an unset ceiling let 50,001 places through")
	}
}
