package triage_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestACommentNeverDisturbsAnApproval(t *testing.T) {
	// The two are different things and the obvious mistake is treating all
	// text on a finding as one. Annotating an approved decision months later
	// is ordinary, and an approval that fell over each time somebody added a
	// note would teach people not to add notes.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.agreed(t, f.at())
		if _, err := f.store.Say(ctx, f.triager, claimed.ClaimID, "Re-checked against 1.2.4; still true."); err != nil {
			t.Fatal(err)
		}

		standing, err := f.store.Applying(ctx, f.at())
		if err != nil {
			t.Fatal(err)
		}
		if standing == nil || standing.State != triage.Approved {
			t.Errorf("a comment disturbed the approval: %+v", standing)
		}
		approvals, err := f.store.Approvals(ctx, f.reviewer, claimed.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if len(approvals) != 1 || approvals[0].WithdrawnAt != nil {
			t.Errorf("a comment withdrew the agreement: %+v", approvals)
		}
	})
}

func TestOnlyTheAuthorMayChangeTheirOwnWords(t *testing.T) {
	// An edit anybody could make is not a correction. It is a forgery with a
	// timestamp.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.agreed(t, f.at())
		said, err := f.store.Say(ctx, f.triager, claimed.ClaimID, "First thought.")
		if err != nil {
			t.Fatal(err)
		}

		if _, err := f.store.Reword(ctx, f.reviewer, said.ID, "Words I did not write."); err == nil {
			t.Error("somebody rewrote another person's comment")
		}
		if _, err := f.store.Reword(ctx, f.triager, said.ID, "Second thought."); err != nil {
			t.Fatal(err)
		}

		discussion, err := f.store.Discussion(ctx, f.triager, claimed.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if len(discussion) != 1 {
			t.Fatalf("%d comments, want 1", len(discussion))
		}
		if discussion[0].Body != "Second thought." {
			t.Errorf("the comment reads %q", discussion[0].Body)
		}
		// Overwritten rather than revised, and marked as changed — discussion
		// is not the record a decision rests on.
		if discussion[0].EditedAt == nil {
			t.Error("an edited comment does not say it was edited")
		}
	})
}

func TestTextOnADecisionGoesThroughTheSamePolicy(t *testing.T) {
	// Every field somebody types into is checked before it is stored, so that
	// stored text is known to have passed what was in force when it arrived.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		const dangerous = "See ![this](https://evil.example/pixel.gif)"

		if _, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.WontFix,
			Reasoning: dangerous, By: f.proposer,
		}); err == nil {
			t.Error("a remote image was accepted as reasoning")
		}

		claimed := f.agreed(t, f.at())
		if _, err := f.store.Revise(ctx, f.triager, claimed.ClaimID, dangerous); err == nil {
			t.Error("a remote image was accepted as a revision")
		}
		if _, err := f.store.Say(ctx, f.triager, claimed.ClaimID, dangerous); err == nil {
			t.Error("a remote image was accepted as a comment")
		}
	})
}

func TestDiscussionIsReadWithoutTheRightToJoinIt(t *testing.T) {
	// the record readable at the finding's visibility widened reading the
	// record to the finding's own visibility, and disclosure opening the
	// record names comments as part of that record. Writing did not move:
	// it had leaned on the reading rule, so widening one would have
	// widened the other and let a reader comment on a decision they may
	// not argue about — which is why the two predicates are named apart.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.agreed(t, f.at())
		if _, err := f.store.Say(ctx, f.onlooker, claimed.ClaimID, "Adding my thoughts."); err == nil {
			t.Error("somebody holding only a read role commented")
		}
		if _, err := f.store.Discussion(ctx, f.onlooker, claimed.ClaimID); err != nil {
			t.Errorf("somebody who may read the finding could not read its discussion: %v", err)
		}
	})
}

func TestARewriteRefusedForOneReasonRatherThanTwo(t *testing.T) {
	// A comment that is not there and a comment on a decision this person
	// may not reach have to answer identically.
	//
	// Refusing on authorship first answered them differently — "only the
	// person who wrote a comment may change it" against "no comment to
	// change" — so anybody holding triage on any product could walk the
	// identifiers and learn which comments exist, including on findings
	// nobody has disclosed. The refusal is the same one and the counting
	// works by hand.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.agreed(t, f.at())
		said, err := f.store.Say(ctx, f.triager, claimed.ClaimID, "Something worth knowing.")
		if err != nil {
			t.Fatal(err)
		}

		// Somebody who may read the product but not argue about it. Two
		// requests: one naming a comment that exists, one naming a number that
		// never has.
		_, here := f.store.Reword(ctx, f.onlooker, said.ID, "Not my words.")
		_, nowhere := f.store.Reword(ctx, f.onlooker, said.ID+9_999, "Not my words.")
		if here == nil || nowhere == nil {
			t.Fatalf("a reader rewrote a comment: existing=%v absent=%v", here, nowhere)
		}
		if here.Error() != nowhere.Error() {
			t.Errorf("a comment that exists is refused as %q and one that does not as %q,\n"+
				"which is how the identifiers get walked", here, nowhere)
		}
		if !errors.Is(here, triage.ErrNotTheirs) {
			t.Errorf("the refusal is %v, which is not the one that answers 'not there'", here)
		}

		// And the author is still refused nothing.
		if _, err := f.store.Reword(ctx, f.triager, said.ID, "Second thought."); err != nil {
			t.Errorf("the author could not change their own comment: %v", err)
		}
	})
}

// A field the text policy admits fits the column on every engine.
//
// The policy bounds typed text at 65,536 bytes and the column held 65,535 on
// two of the four, so a justification of exactly the admitted size passed
// submission and failed the write on MySQL and MariaDB — or was truncated
// silently outside strict mode, which leaves an approver agreeing to words
// that are not the words that were written. The quick loop never saw it,
// because SQLite stores it happily.
func TestTextThePolicyAdmitsFitsTheColumn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// Exactly what the policy admits, in plain prose so nothing else
		// refuses it.
		reasoning := strings.Repeat("a", markdown.MaxBytes)
		if err := markdown.Check(reasoning); err != nil {
			t.Fatalf("the policy refuses what it says it admits: %v", err)
		}

		made, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.WontFix,
			Reasoning: reasoning, By: f.proposer,
		})
		if err != nil {
			t.Fatalf("a field of exactly the admitted size could not be stored: %v", err)
		}
		kept, err := f.store.ReasoningFor(ctx, []triage.Decision{*made})
		if err != nil {
			t.Fatal(err)
		}
		if len(kept[made.ID]) != len(reasoning) {
			t.Errorf("%d bytes were written and %d came back",
				len(reasoning), len(kept[made.ID]))
		}
	})
}
