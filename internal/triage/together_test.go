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

		_, recorded, err := f.store.Together(ctx, f.triager, triage.TogetherAt{
			TargetID: in.target, ComponentID: libfoo, VulnerabilityIDs: []int64{f.issue},
		}, triage.Proposal{
			Outcome: triage.NotApplicable, Justification: triage.CodeNotInExecutePath,
			Reasoning: "The parser is never reached: we only call the encoder.",
			By:        f.proposer, NeedsApproval: true,
		}, triage.DefaultTogetherCap)
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
		if written.SeverityAtApproval() != want {
			t.Errorf("the baseline reads as %d, want %d — the rating in force here, "+
				"not the published score", written.SeverityAtApproval(), want)
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
		_, recorded, err := f.store.Together(ctx, f.triager, at, claim, triage.DefaultTogetherCap)
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) != 1 {
			t.Fatalf("%d decisions recorded, want the one place", len(recorded))
		}

		// The same selection again, which now collides with what it wrote.
		_, _, err = f.store.Together(ctx, f.triager, at, claim, triage.DefaultTogetherCap)
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("a second claim was recorded over the first: %v", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprint(recorded[0])) {
			t.Errorf("the refusal does not name the decision that stands: %v", err)
		}
	})
}
