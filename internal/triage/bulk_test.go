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

func TestABulkDecisionRecordsTheRatingInForceAsItsBaseline(t *testing.T) {
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
			Set(`"score_centi" = ?`, 980).Set(`"severity" = ?`, "critical").
			Where(`"id" = ?`, f.issue).Exec(ctx); err != nil {
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

		_, recorded, _, err := f.store.BulkDecision(ctx, f.triager, triage.BulkDecisionAt{
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
			t.Fatalf("%d rows recorded, want the one occurrence", len(recorded))
		}

		var written triage.DecisionOccurrence
		if err := f.db.DB.NewSelect().Model(&written).
			Where(`"id" = ?`, recorded[0]).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		want := finding.SeverityScore("medium")
		if written.SeverityCenti == nil || *written.SeverityCenti != want {
			t.Errorf("the baseline reads as %v, want %d — the rating in force here, "+
				"not the published score", written.SeverityCenti, want)
		}
	})
}

func TestABulkDecisionNamesTheDecisionThatBlockedIt(t *testing.T) {
	// One live decision per combination of code holds here as it does anywhere,
	// so a selection covering something already decided is refused whole.
	// "Something in this selection is already decided" tells somebody holding
	// five hundred rows nothing they can act on, while the single-finding path
	// names the decision to go and revise. One spelling, and it names which.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.build(t, f.product, "2026.03")
		libfoo := f.component(t, "libfoo", "1.2.3")
		f.finds(t, in, libfoo, "place-of-libfoo", access.Public)

		at := triage.BulkDecisionAt{
			TargetID: in.target, ComponentID: libfoo, VulnerabilityIDs: []int64{f.issue},
		}
		decision := triage.Proposal{
			Outcome: triage.NotApplicable, Justification: triage.CodeNotInExecutePath,
			Reasoning: "The parser is never reached: we only call the encoder.",
			By:        f.proposer, NeedsApproval: true,
		}
		_, recorded, _, err := f.store.BulkDecision(ctx, f.triager, at, decision, triage.DefaultBounds())
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) != 1 {
			t.Fatalf("%d rows recorded, want the one occurrence", len(recorded))
		}

		// The same selection again, which now collides with what it wrote.
		_, _, _, err = f.store.BulkDecision(ctx, f.triager, at, decision, triage.DefaultBounds())
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("a second decision was recorded over the first: %v", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprint(recorded[0])) {
			t.Errorf("the refusal does not name the decision that stands: %v", err)
		}
	})
}

func TestABulkDecisionAskedToSkipLeavesOutWhatIsDecidedAndNamesIt(t *testing.T) {
	// Skipping is something the proposer asks for, and what it left out is
	// said: a decision covering less than was selected is one the proposer can
	// see is smaller, and the decision standing at each skipped occurrence is where
	// they go next.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		both := f.twoIssues(t)
		first := both
		first.VulnerabilityIDs = both.VulnerabilityIDs[:1]
		_, standing, _, err := f.store.BulkDecision(ctx, f.triager, first, f.wontFix(),
			triage.DefaultBounds())
		if err != nil {
			t.Fatal(err)
		}

		// Unasked, the selection is refused whole.
		if _, _, _, err := f.store.BulkDecision(ctx, f.triager, both, f.wontFix(),
			triage.DefaultBounds()); !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("a selection covering a decided occurrence was not refused: %v", err)
		}

		both.SkipDecided = true
		_, recorded, skipped, err := f.store.BulkDecision(ctx, f.triager, both,
			f.wontFix(), triage.DefaultBounds())
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) != 1 {
			t.Errorf("%d rows recorded, want the one undecided occurrence", len(recorded))
		}
		if len(skipped) != 1 || skipped[0].DecisionOccurrenceID != standing[0] ||
			skipped[0].VulnerabilityID != both.VulnerabilityIDs[0] {
			t.Errorf("what was skipped reads %+v, want decision occurrence %d on the first issue",
				skipped, standing[0])
		}

		// Everything decided now: nothing to decide, and nothing written.
		if _, _, _, err := f.store.BulkDecision(ctx, f.triager, both, f.wontFix(),
			triage.DefaultBounds()); !errors.Is(err, triage.ErrAllDecided) {
			t.Errorf("a selection that is all decided answered %v", err)
		}
	})
}

func TestABulkDecisionsCapCountsWhatItWritesAfterSkipping(t *testing.T) {
	// The bound is on rows written. An occurrence skipped is not written, so a
	// selection that would pass the cap once its decided occurrences are left out
	// is not refused for them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		both := f.twoIssues(t)
		first := both
		first.VulnerabilityIDs = both.VulnerabilityIDs[:1]
		one := triage.Bounds{Review: 1, Occurrences: 1}
		if _, _, _, err := f.store.BulkDecision(ctx, f.triager, first, f.wontFix(), one); err != nil {
			t.Fatal(err)
		}
		both.SkipDecided = true
		if _, recorded, _, err := f.store.BulkDecision(ctx, f.triager, both,
			f.wontFix(), one); err != nil || len(recorded) != 1 {
			t.Errorf("a decision writing one occurrence under a cap of one answered %v, %d written",
				err, len(recorded))
		}
	})
}

func TestTheIssueLimitIsTheReviewersWhereAnythingGoesToASecondPerson(t *testing.T) {
	// Re-confirming what was already agreed to asks nobody to read anything
	// new, so it takes the larger limit; anything that goes back to an
	// approver takes the reviewer's. The occurrence ceiling holds either way.
	b := triage.Bounds{Review: 2, Agreed: 5, Occurrences: 10}
	for _, each := range []struct {
		issues, occurrences int
		review, refused     bool
	}{
		{2, 10, true, false},
		{3, 3, true, true},
		{5, 5, false, false},
		{6, 6, false, true},
		{1, 11, false, true},
		{1, 11, true, true},
	} {
		err := b.Counted(each.issues, each.occurrences, each.review)
		if (err != nil) != each.refused {
			t.Errorf("%d issues at %d occurrences, review %v: refused %v, want %v (%v)",
				each.issues, each.occurrences, each.review, err != nil, each.refused, err)
		}
	}
	// Unset is the shipped limits, never unbounded.
	if err := (triage.Bounds{}).Counted(1, 50001, false); err == nil {
		t.Error("an unset ceiling let 50,001 occurrences through")
	}
}
