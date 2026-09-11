package triage_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/schema"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// fixture is a product, an issue and two people, which is the least a decision
// needs: one to make a claim and one to agree with it.
type fixture struct {
	db      *database.DB
	store   *triage.Store
	product int64
	issue   int64
	proposer,
	approver int64
	// The subjects those two act as. Triage is a right held per product and
	// per visibility, so every call carries one.
	triager, reviewer, onlooker access.Subject
}

// at is a place to decide about, defaulting to versions that make the
// straightforward case straightforward.
func (f *fixture) at() triage.Place {
	return triage.Place{
		ProductID: f.product, VulnerabilityID: f.issue,
		PlaceIdentity:     "place-of-libfoo-under-libbar",
		Visibility:        access.Public,
		ComponentUpstream: "1.2.3", ConsumerUpstream: "4.5.6",
	}
}

// claims a not-applicable decision, which is the shape everything else builds on.
func (f *fixture) claims(t *testing.T, at triage.Place) *triage.Decision {
	t.Helper()
	decision, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
		Place: at, Outcome: triage.NotApplicable,
		Justification: triage.CodeNotInExecutePath,
		Reasoning:     "The parser is never reached: we only call the encoder.",
		By:            f.proposer,
		// What a caller works out through NeedsApproval and passes in.
		// Dismissing something as not applicable hides risk, so it waits.
		NeedsApproval: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

// agreed is a claim that has been through review and now stands. Most tests
// here are about what happens to a standing decision — it expires, it lapses,
// somebody comments on it — and reaching that state is a precondition rather
// than the subject.
func (f *fixture) agreed(t *testing.T, at triage.Place) *triage.Decision {
	t.Helper()
	claimed := f.claims(t, at)
	if err := agreeTo(t.Context(), f.store, f.reviewer, claimed.ClaimID, ""); err != nil {
		t.Fatal(err)
	}
	return claimed
}

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		product, err := catalog.NewStore(db.DB).DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		interned, err := finding.NewVulnerabilities(db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-1", Severity: "high"},
		})
		if err != nil {
			t.Fatal(err)
		}
		issue := interned["CVE-2026-1"]
		rights := access.NewStore(db.DB)
		one, err := rights.Ensure(ctx, "proposer", "", false)
		if err != nil {
			t.Fatal(err)
		}
		two, err := rights.Ensure(ctx, "approver", "", false)
		if err != nil {
			t.Fatal(err)
		}
		none, err := rights.Ensure(ctx, "onlooker", "", false)
		if err != nil {
			t.Fatal(err)
		}
		for _, who := range []int64{one.ID, two.ID} {
			if err := rights.GrantRole(ctx, who, product.ID, access.PublicTriage); err != nil {
				t.Fatal(err)
			}
		}
		// Reading is not deciding: this one may see the product and may argue
		// about nothing on it.
		if err := rights.GrantRole(ctx, none.ID, product.ID, access.PublicRead); err != nil {
			t.Fatal(err)
		}

		subject := func(identity string) access.Subject {
			resolved, err := rights.Resolve(ctx, identity)
			if err != nil {
				t.Fatal(err)
			}
			return resolved
		}

		fn(t, &fixture{
			db: db, store: triage.NewStore(db.DB), product: product.ID, issue: issue,
			proposer: one.ID, approver: two.ID,
			triager: subject("proposer"), reviewer: subject("approver"), onlooker: subject("onlooker"),
		})
	})
}

func TestAClaimStandsOnlyOnceSomebodyHasAgreedToIt(t *testing.T) {
	// The control, stated as behavior rather than as a state name. A claim
	// that hides risk suppresses nothing while it waits — otherwise one person
	// dismisses a finding on their own and the review queue is decorative.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.claims(t, f.at())

		if standing, _ := f.store.Applying(ctx, f.at()); standing != nil {
			t.Error("a claim nobody has agreed to already suppresses the finding")
		}

		if err := agreeTo(ctx, f.store, f.reviewer, claimed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		standing, err := f.store.Applying(ctx, f.at())
		if err != nil {
			t.Fatal(err)
		}
		if standing == nil || standing.ID != claimed.ID {
			t.Fatalf("an agreed claim does not apply where it was made: %+v", standing)
		}
		if standing.Claim.RevisionID == nil {
			t.Error("a decision was recorded with no reasoning to read")
		}
	})
}

func TestAClaimThatNeedsNobodyTakesEffectAtOnce(t *testing.T) {
	// The other half. A quick "not this sprint" is ordinary triage, and making
	// it wait for a second person would put every routine act through a queue
	// — which is how a queue stops being read.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		soon := time.Now().UTC().Add(7 * 24 * time.Hour)
		if _, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.Deferred, DeferredUntil: &soon,
			Reasoning: "Not this sprint.", By: f.proposer, NeedsApproval: false,
		}); err != nil {
			t.Fatal(err)
		}
		if standing, _ := f.store.Applying(ctx, f.at()); standing == nil {
			t.Error("a short deferral did not take effect until somebody agreed")
		}
	})
}

func TestAnAgreedClaimCannotBeShadowedByALaterOne(t *testing.T) {
	// This used to check that a claim nobody had agreed to did not shadow an
	// agreed one, because both could exist and what applied was chosen by
	// agreed-beats-waiting and then newest-wins. The second claim can no
	// longer be made at all, so the shadowing has nowhere to come from — and
	// the refusal names the decision to go and revise instead.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.agreed(t, f.at())

		_, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.WontFix,
			Reasoning: "Actually we are never fixing this.", By: f.proposer,
			NeedsApproval: true,
		})
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("a claim was recorded beside an agreed one: %v", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprint(agreed.ID)) {
			t.Errorf("the refusal does not name the agreed decision: %v", err)
		}

		// And what stands is still the agreed claim, untouched.
		standing, err := f.store.Applying(ctx, f.at())
		if err != nil {
			t.Fatal(err)
		}
		if standing == nil || standing.ID != agreed.ID {
			t.Errorf("the agreed decision no longer stands: %+v", standing)
		}
	})
}

func TestAnUpstreamVersionMovingLapsesADecision(t *testing.T) {
	// Expiry is not a mechanism. The decision was stored under the versions it
	// was a claim about, and a place asks under the versions it has now — so
	// when the code moves, the keys stop matching and the claim stops
	// standing. Nothing sweeps and nothing runs on a timer.
	each(t, func(t *testing.T, f *fixture) {
		f.agreed(t, f.at())

		for _, moved := range []struct {
			what  string
			place triage.Place
		}{
			{"the component's upstream version", func() triage.Place {
				p := f.at()
				p.ComponentUpstream = "1.2.4"
				return p
			}()},
			{"the consumer's upstream version", func() triage.Place {
				p := f.at()
				p.ConsumerUpstream = "4.5.7"
				return p
			}()},
			{"the place itself", func() triage.Place {
				p := f.at()
				p.PlaceIdentity = "somewhere-else"
				return p
			}()},
			{"the issue", func() triage.Place {
				p := f.at()
				p.VulnerabilityID = f.issue + 1000
				return p
			}()},
		} {
			standing, err := f.store.Applying(t.Context(), moved.place)
			if err != nil {
				t.Fatal(err)
			}
			if standing != nil {
				t.Errorf("the decision still stood after %s changed", moved.what)
			}
		}
	})
}

func TestARebuildDoesNotLapseADecision(t *testing.T) {
	// The reason only upstream versions are compared. A shipped package is
	// rebuilt constantly and carries a version of its own that moves each
	// time — and a rebuild is not somebody's reasoning becoming wrong. If the
	// shipped version were compared, every decision would lapse nightly and
	// the tool would be unusable by the second week.
	each(t, func(t *testing.T, f *fixture) {
		f.agreed(t, f.at())

		// Same upstream, and everything about how it was packaged has moved.
		// The place is derived from names, so a repackage does not touch it.
		rebuilt := f.at()
		standing, err := f.store.Applying(t.Context(), rebuilt)
		if err != nil {
			t.Fatal(err)
		}
		if standing == nil {
			t.Error("a decision lapsed on a rebuild that changed no upstream version")
		}
	})
}

func TestADecisionIsFoundAgainAfterItLapses(t *testing.T) {
	// Making somebody re-decide from a blank page, having thrown away what was
	// written last time, is how a tool teaches people to stop writing
	// reasoning at all.
	each(t, func(t *testing.T, f *fixture) {
		f.agreed(t, f.at())

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		if standing, _ := f.store.Applying(t.Context(), moved); standing != nil {
			t.Fatal("the decision should not stand at the moved version")
		}

		previous, err := f.store.PreviouslyAt(t.Context(), f.reviewer, moved)
		if err != nil {
			t.Fatal(err)
		}
		if len(previous) != 1 {
			t.Fatalf("found %d earlier decisions about this place, want 1", len(previous))
		}
		if previous[0].ComponentUpstreamVersion == nil || *previous[0].ComponentUpstreamVersion != "1.2.3" {
			t.Error("what came back does not say which version it was a claim about")
		}
	})
}

func TestNobodyApprovesTheirOwnClaim(t *testing.T) {
	// No override. A deployment with one person cannot approve anything, which
	// is the control working rather than a gap in it.
	each(t, func(t *testing.T, f *fixture) {
		claimed := f.claims(t, f.at())

		if err := agreeTo(t.Context(), f.store, f.triager, claimed.ClaimID, ""); !errors.Is(err, triage.ErrSamePerson) {
			t.Errorf("somebody approved their own claim: %v", err)
		}
		if err := agreeTo(t.Context(), f.store, f.reviewer, claimed.ClaimID, ""); err != nil {
			t.Errorf("a second person could not approve: %v", err)
		}
	})
}

func TestRevisingTheReasoningTakesBackTheApproval(t *testing.T) {
	// The control, and the way it fails silently if this is wrong. A second
	// person agreed to particular words; different words are a claim nobody
	// has agreed to, and an approval carrying over would leave the record
	// saying two people had read something only one of them had.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.agreed(t, f.at())

		if _, err := f.store.Revise(ctx, f.triager, claimed.ClaimID,
			"Actually the parser is reached, but only from a path we control."); err != nil {
			t.Fatal(err)
		}

		// The finding is exposed again while the new words wait for somebody,
		// which is the whole point: what one person wrote suppresses nothing
		// on its own.
		standing, err := f.store.Applying(ctx, f.at())
		if err != nil {
			t.Fatal(err)
		}
		if standing != nil {
			t.Fatalf("revised words suppressed the finding before anybody agreed: %+v", standing)
		}
		waiting, _, err := f.store.Queue(ctx, f.reviewer, false, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != 1 || waiting[0].Decision.ID != claimed.ID {
			t.Errorf("the revised claim is waiting for nobody: %+v", waiting)
		}

		approvals, err := f.store.Approvals(ctx, f.reviewer, claimed.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if len(approvals) != 1 || approvals[0].WithdrawnAt == nil {
			t.Errorf("the approval on the old words is still standing: %+v", approvals)
		}

		// And what was agreed to is still readable, which is the point of
		// keeping revisions rather than overwriting them.
		revisions, err := f.store.Revisions(ctx, f.reviewer, claimed.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if len(revisions) != 2 {
			t.Fatalf("kept %d revisions, want 2", len(revisions))
		}
		if revisions[0].ID != approvals[0].RevisionID {
			t.Error("the approval does not name the words that were approved")
		}
	})
}

func TestADeferralStopsStandingOnItsDate(t *testing.T) {
	// A different claim, so a different mechanism: a version bump does not
	// change a judgment about priority, and a calendar does not change one
	// about applicability.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		soon := time.Now().UTC().Add(24 * time.Hour)
		if _, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.Deferred, DeferredUntil: &soon,
			Reasoning: "Not this sprint.", By: f.proposer,
		}); err != nil {
			t.Fatal(err)
		}
		if standing, _ := f.store.Applying(ctx, f.at()); standing == nil {
			t.Error("a deferral did not stand before its date")
		}

		// The other half, recorded the only way it can happen: a deferral is
		// written with a date still to come — one already gone is refused —
		// and the date then arrives. Moved here rather than waited for.
		lapsedPlace := f.at()
		lapsedPlace.PlaceIdentity = "another-place"
		ran, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: lapsedPlace, Outcome: triage.Deferred, DeferredUntil: &soon,
			Reasoning: "Was not that sprint either.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		past := time.Now().UTC().Add(-time.Hour)
		if _, err := f.db.DB.NewUpdate().Table("claim").
			Set("deferred_until = ?", past).
			Where("id = ?", ran.ClaimID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if standing, _ := f.store.Applying(ctx, lapsedPlace); standing != nil {
			t.Error("a deferral still stood after its date had passed")
		}
	})
}

func TestAClaimHasToSayEnoughToBeAgreedWith(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		for _, c := range []struct {
			what string
			p    triage.Proposal
		}{
			{"no reasoning", triage.Proposal{Place: f.at(), Outcome: triage.WontFix, By: f.proposer}},
			{"no outcome", triage.Proposal{Place: f.at(), Reasoning: "x", By: f.proposer}},
			{"nobody making it", triage.Proposal{Place: f.at(), Outcome: triage.WontFix, Reasoning: "x"}},
			{"not-applicable with no reason", triage.Proposal{
				Place: f.at(), Outcome: triage.NotApplicable, Reasoning: "x", By: f.proposer}},
			{"not-applicable with an unrecognized reason", triage.Proposal{
				Place: f.at(), Outcome: triage.NotApplicable, Justification: "because-i-say-so",
				Reasoning: "x", By: f.proposer}},
			{"a deferral with no date to return on", triage.Proposal{
				Place: f.at(), Outcome: triage.Deferred, Reasoning: "x", By: f.proposer}},
			{"a reason on a claim that is not about applicability", triage.Proposal{
				Place: f.at(), Outcome: triage.WontFix, Justification: triage.CodeNotPresent,
				Reasoning: "x", By: f.proposer}},
		} {
			if _, err := f.store.Propose(t.Context(), f.triager, c.p); err == nil {
				t.Errorf("a claim with %s was recorded", c.what)
			}
		}
	})
}

func TestABulkApprovalIsUndoneAsABatch(t *testing.T) {
	// A reviewer may agree to a long selection in one action, so undoing has
	// to be available at the same size. Hunting for what a bulk approval
	// touched, one row at a time, is not an undo anybody will use.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		const batch = "one-afternoon"
		var made, claims []int64
		for _, place := range []string{"a", "b", "c"} {
			at := f.at()
			at.PlaceIdentity = place
			decision := f.claims(t, at)
			made = append(made, decision.ID)
			claims = append(claims, decision.ClaimID)
			if err := agreeTo(ctx, f.store, f.reviewer, decision.ClaimID, batch); err != nil {
				t.Fatal(err)
			}
		}

		undone, err := f.store.UndoBatch(ctx, f.reviewer, batch)
		if err != nil {
			t.Fatal(err)
		}
		if undone.Rows != int64(len(made)) {
			t.Errorf("undid %d of %d", undone.Rows, len(made))
		}
		// And the proposer is named once, whatever it covered: an undo
		// is one of the two outcomes they are told about.
		if len(undone.Told) != 1 || undone.Told[0].Rows != len(made) {
			t.Errorf("an undo of %d rows names %+v to tell", len(made), undone.Told)
		}
		// One agreement per claim, taken back: an approver agreed to the
		// argument once, so undoing that batch is one withdrawal however many
		// places it covered.
		for _, claimID := range claims {
			approvals, err := f.store.Approvals(ctx, f.reviewer, claimID)
			if err != nil {
				t.Fatal(err)
			}
			if len(approvals) != 1 || approvals[0].WithdrawnAt == nil {
				t.Errorf("claim %d is still approved", claimID)
			}
		}
		// The claims themselves survive — it is the agreement that was taken
		// back, not the reasoning — so each one is waiting for an approver
		// again rather than gone. Meanwhile nothing they said is suppressing
		// anything, because nobody has agreed to it.
		at := f.at()
		at.PlaceIdentity = "a"
		if standing, _ := f.store.Applying(ctx, at); standing != nil {
			t.Errorf("an undone approval still suppresses the finding: %+v", standing)
		}
		waiting, _, err := f.store.Queue(ctx, f.reviewer, false, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != len(made) {
			t.Errorf("%d claims came back to the queue, want %d", len(waiting), len(made))
		}
	})
}

func TestDecidingIsItsOwnRight(t *testing.T) {
	// Reading a finding is not judging it. Somebody who may see a product and
	// holds no triage on it reaches every decision about it and may make none
	// — which is the difference between an approver, a reporter and a triager.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := f.store.Propose(ctx, f.onlooker, triage.Proposal{
			Place: f.at(), Outcome: triage.WontFix,
			Reasoning: "I should not be able to say this.", By: f.onlooker.ID,
		}); !errors.Is(err, triage.ErrNotTheirs) {
			t.Errorf("somebody holding only a read role made a decision: %v", err)
		}

		claimed := f.agreed(t, f.at())
		if err := agreeTo(ctx, f.store, f.onlooker, claimed.ClaimID, ""); !errors.Is(err, triage.ErrNotTheirs) {
			t.Errorf("somebody holding only a read role approved one: %v", err)
		}
		if _, err := f.store.Revise(ctx, f.onlooker, claimed.ClaimID, "words"); !errors.Is(err, triage.ErrNotTheirs) {
			t.Errorf("somebody holding only a read role revised one: %v", err)
		}
		if err := f.store.Withdraw(ctx, f.onlooker, claimed.ClaimID); !errors.Is(err, triage.ErrNotTheirs) {
			t.Errorf("somebody holding only a read role withdrew one: %v", err)
		}
	})
}

func TestTriagingOneProductIsNotTriagingAnother(t *testing.T) {
	// Every right here is held against a product. A claim about a product
	// somebody holds nothing on is refused, and refused the same way a claim
	// about one that does not exist is — so guessing identifiers says nothing.
	each(t, func(t *testing.T, f *fixture) {
		elsewhere := f.at()
		elsewhere.ProductID = f.product + 1000
		if _, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
			Place: elsewhere, Outcome: triage.WontFix,
			Reasoning: "About a product I hold nothing on.", By: f.proposer,
		}); !errors.Is(err, triage.ErrNotTheirs) {
			t.Errorf("a triager reached another product: %v", err)
		}
	})
}

func TestArguingAboutSomethingUndisclosedNeedsThatRight(t *testing.T) {
	// The two triage roles are not one. Somebody trusted with what has been
	// disclosed is not thereby trusted with what has not.
	each(t, func(t *testing.T, f *fixture) {
		undisclosed := f.at()
		undisclosed.Visibility = access.Private

		if _, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
			Place: undisclosed, Outcome: triage.WontFix,
			Reasoning: "About something not yet disclosed.", By: f.proposer,
		}); !errors.Is(err, triage.ErrNotTheirs) {
			t.Errorf("a public triager argued about an undisclosed finding: %v", err)
		}
	})
}

func TestAClaimIsRecordedAsMadeByWhoeverMadeIt(t *testing.T) {
	// Otherwise the second-person rule means nothing: anybody could propose
	// under another name and then agree with themselves.
	each(t, func(t *testing.T, f *fixture) {
		if _, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.WontFix,
			Reasoning: "Recorded as somebody else.", By: f.approver,
		}); err == nil {
			t.Error("a decision was recorded as made by somebody who did not make it")
		}
	})
}

func TestUndoingABatchTouchesOnlyWhatTheUndoerMayReach(t *testing.T) {
	// A batch is one reviewer's afternoon and may span products. Undoing it
	// wholesale would let somebody act on products they hold nothing on.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		const batch = "one-afternoon"
		claimed := f.claims(t, f.at())
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.ClaimID, batch); err != nil {
			t.Fatal(err)
		}

		undone, err := f.store.UndoBatch(ctx, f.onlooker, batch)
		if err != nil {
			t.Fatal(err)
		}
		if undone.Rows != 0 {
			t.Errorf("somebody holding only a read role undid %d approvals", undone.Rows)
		}
		if len(undone.Told) != 0 {
			t.Errorf("an undo that touched nothing has somebody to tell: %+v", undone.Told)
		}
		approvals, err := f.store.Approvals(ctx, f.reviewer, claimed.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if approvals[0].WithdrawnAt != nil {
			t.Error("the approval was taken back by somebody who may not triage")
		}
	})
}

func TestAPlaceThatStatesNoVisibilityIsTreatedAsUndisclosed(t *testing.T) {
	// A place is assembled by whatever asked, and something that forgot to
	// state this would otherwise make an undisclosed finding argueable by
	// anybody who can triage the disclosed ones. Unset has to read as the
	// careful answer, not the convenient one.
	each(t, func(t *testing.T, f *fixture) {
		unstated := f.at()
		unstated.Visibility = ""

		if _, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
			Place: unstated, Outcome: triage.WontFix,
			Reasoning: "About something whose visibility nobody stated.", By: f.proposer,
		}); !errors.Is(err, triage.ErrNotTheirs) {
			t.Errorf("a public triager decided about a place stating no visibility: %v", err)
		}
	})
}

func TestAVersionIsReadTheSameWayItIsWritten(t *testing.T) {
	// Surrounding space is not part of a version, and the two halves used to
	// disagree about that: storing treated a whitespace-only version as absent
	// while matching treated it as a version that happened to be spaces. A
	// decision written against nothing then looked for something, and could
	// never apply to the place it was made about — silently, since nothing
	// about it looks wrong from either side.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		spaced := f.at()
		spaced.ComponentUpstream = "  1.2.3  "
		spaced.ConsumerUpstream = "   "

		claimed, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: spaced, Outcome: triage.WontFix,
			Reasoning: "Not worth it.", By: f.proposer, NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}

		// The same place, written the ordinary way.
		plain := f.at()
		plain.ComponentUpstream = "1.2.3"
		plain.ConsumerUpstream = ""
		standing, err := f.store.Applying(ctx, plain)
		if err != nil {
			t.Fatal(err)
		}
		if standing == nil || standing.ID != claimed.ID {
			t.Fatalf("a decision written with spaces around its version does not apply: %+v", standing)
		}

		// And the other direction: a place whose versions arrive with space
		// around them finds the decision stored without it. Both halves have
		// to trim, or one of them decides what the other cannot find.
		alsoSpaced := f.at()
		alsoSpaced.ComponentUpstream = " 1.2.3 "
		alsoSpaced.ConsumerUpstream = "  "
		if standing, _ := f.store.Applying(ctx, alsoSpaced); standing == nil {
			t.Error("a place stated with spaces did not find the decision made about it")
		}

		// And it still expires: trimming must not turn every version into a
		// match.
		moved := plain
		moved.ComponentUpstream = "1.2.4"
		if standing, _ := f.store.Applying(ctx, moved); standing != nil {
			t.Error("the decision stood at a version it was not made about")
		}
	})
}

func TestOnlyOneLiveDecisionCoversOneCombinationOfCode(t *testing.T) {
	// Two people making contradictory claims about one finding is a
	// disagreement, and a disagreement belongs in one place where both sides
	// are readable. Before this, both claims sat in the queue looking
	// ordinary, and approving both left one silently governing while the other
	// stayed on the record as agreed — with neither approver aware of the
	// other.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := f.claims(t, f.at())

		_, err := f.store.Propose(ctx, f.reviewer, triage.Proposal{
			Place: f.at(), Outcome: triage.WontFix,
			Reasoning: "Actually we are never fixing this.", By: f.approver,
			NeedsApproval: true,
		})
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("a second claim about the same code was accepted: %v", err)
		}
		// And the refusal says which one to go and read.
		if !strings.Contains(err.Error(), fmt.Sprint(first.ID)) {
			t.Errorf("the refusal does not name the decision already standing: %v", err)
		}
	})
}

func TestADeadDecisionDoesNotBlockThePlaceForever(t *testing.T) {
	// History must not stop anybody deciding. A withdrawn claim covers
	// nothing, and a lapsed one covers nothing either — so the place has to be
	// open to a fresh claim, or one lapse would wall it off permanently.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.claims(t, f.at())
		if err := f.store.Withdraw(ctx, f.triager, claimed.ClaimID); err != nil {
			t.Fatal(err)
		}

		again, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.WontFix,
			Reasoning: "Different answer, now that the first was taken back.",
			By:        f.proposer, NeedsApproval: true,
		})
		if err != nil {
			t.Fatalf("a withdrawn claim blocked the place: %v", err)
		}
		if again.ID == claimed.ID {
			t.Error("the withdrawn decision was reused rather than a new one recorded")
		}
	})
}

func TestTheSamePlaceAtAnotherVersionIsItsOwnClaim(t *testing.T) {
	// The uniqueness is per combination of code, not per place. A claim about
	// one version and a claim about the next are different claims, and both
	// standing is how carrying a judgment forward works at all.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.claims(t, f.at())

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		if _, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: moved, Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath,
			Reasoning:     "Still not reached at the new version.",
			By:            f.proposer, NeedsApproval: true,
		}); err != nil {
			t.Fatalf("a claim about another version was refused: %v", err)
		}
	})
}

func TestTwoPeopleProposingAtOnceProduceOneClaim(t *testing.T) {
	// The reason this is a unique index rather than a check. Two proposals
	// arriving together both pass anything read before the write, so the rule
	// has to be enforced where the write happens.
	each(t, func(t *testing.T, f *fixture) {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, who := range []access.Subject{f.triager, f.reviewer} {
			by := []int64{f.proposer, f.approver}[i]
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = f.store.Propose(context.WithoutCancel(t.Context()), who,
					triage.Proposal{
						Place: f.at(), Outcome: triage.WontFix,
						Reasoning: "Racing.", By: by, NeedsApproval: true,
					})
			}()
		}
		wg.Wait()

		won := 0
		for _, err := range errs {
			if err == nil {
				won++
			}
		}
		if won != 1 {
			t.Fatalf("%d of two simultaneous proposals were recorded, want exactly one", won)
		}

		var live int
		if err := f.db.NewSelect().Model((*triage.Decision)(nil)).
			Where("live_key IS NOT NULL").Scan(t.Context(), &live); err == nil && live > 1 {
			t.Errorf("%d live claims cover one combination of code", live)
		}
	})
}

func TestSendingAClaimBackTakesItOutOfTheQueueUntilItIsAnswered(t *testing.T) {
	// The third thing an approver needs. Approve and withdraw were the only
	// two, and withdrawing throws away somebody's work over a missing
	// sentence — so what actually happened was a comment, and the claim sat in
	// the queue looking untouched.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.claims(t, f.at())

		if waiting, _, _ := f.store.Queue(ctx, f.reviewer, false, 10, 0); len(waiting) != 1 {
			t.Fatalf("%d claims are waiting before it is sent back", len(waiting))
		}

		// A reason is the whole point of the action.
		if _, err := f.store.SendBackClaim(ctx, f.reviewer, claimed.ClaimID, "   "); err == nil {
			t.Error("a claim was sent back with no reason")
		}
		if _, err := f.store.SendBackClaim(ctx, f.reviewer, claimed.ClaimID,
			"This does not say how the config was checked after the bump."); err != nil {
			t.Fatal(err)
		}

		if waiting, _, _ := f.store.Queue(ctx, f.reviewer, false, 10, 0); len(waiting) != 0 {
			t.Errorf("%d claims still wait on an approver after being sent back", len(waiting))
		}
		// The reason is where the author will read it.
		said, err := f.store.Discussion(ctx, f.triager, claimed.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if len(said) != 1 || !strings.Contains(said[0].Body, "how the config was checked") {
			t.Errorf("the reason is not in the discussion: %+v", said)
		}
		// And it still suppresses nothing, which it never did.
		if standing, _ := f.store.Applying(ctx, f.at()); standing != nil {
			t.Error("a claim sent back is suppressing the finding")
		}
	})
}

func TestAnsweringWhatWasAskedPutsItBackInTheQueue(t *testing.T) {
	// Otherwise sending something back is a way of losing it, and nobody would
	// use it twice.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.claims(t, f.at())
		if _, err := f.store.SendBackClaim(ctx, f.reviewer, claimed.ClaimID, "Say how you checked."); err != nil {
			t.Fatal(err)
		}

		if _, err := f.store.Revise(ctx, f.triager, claimed.ClaimID,
			"Checked against the build script at line 40, which pins the ciphers."); err != nil {
			t.Fatal(err)
		}
		waiting, _, err := f.store.Queue(ctx, f.reviewer, false, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != 1 {
			t.Errorf("%d claims wait on an approver after being answered, want 1", len(waiting))
		}
	})
}

func TestNobodySendsTheirOwnWordsBack(t *testing.T) {
	// That is theirs to revise. Sending your own claim back is a way of
	// putting it out of everybody's sight, including your own.
	each(t, func(t *testing.T, f *fixture) {
		claimed := f.claims(t, f.at())
		if _, err := f.store.SendBackClaim(t.Context(), f.triager, claimed.ClaimID,
			"Actually let me think again."); err == nil {
			t.Error("somebody sent their own claim back")
		}
	})
}

func TestAnApprovalKeepsWhatItCoveredAtTheTime(t *testing.T) {
	// A decision reaches by matching, so it covers more as builds appear —
	// with nobody acting, and nobody having agreed to the larger number.
	// Asking later what it covers answers a different question from what
	// somebody consented to, and only one of the two survives if it is not
	// written down when it happens.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.claims(t, f.at())
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}

		approvals, err := f.store.Approvals(ctx, f.reviewer, claimed.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if len(approvals) != 1 {
			t.Fatalf("%d approvals recorded", len(approvals))
		}
		if approvals[0].Covered == nil {
			t.Fatal("the approval does not say how much it covered")
		}
		// This fixture has no findings behind the place, so the honest answer
		// is none — what matters is that the number was taken and kept rather
		// than left to be worked out later.
		if *approvals[0].Covered != 0 {
			t.Errorf("recorded covering %d, want the count at the time", *approvals[0].Covered)
		}
	})
}

func TestAClaimThatSomethingElseStopsItMustSayWhat(t *testing.T) {
	// Every other reason for something not applying is a claim about code,
	// and code is what makes a claim lapse: the version moves and somebody
	// is asked again. This one is a claim about configuration, which can
	// be removed with nothing moving at all, so nothing here will notice.
	// Naming the control does not close that gap — it makes the claim
	// something the next person can go and check.
	each(t, func(t *testing.T, f *fixture) {
		_, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.NotApplicable,
			Justification: triage.MitigationsExist,
			Reasoning:     "Something else stops it.",
			By:            f.proposer, NeedsApproval: true,
		})
		if err == nil {
			t.Fatal("a claim that mitigations exist was recorded without saying what they are")
		}

		decision, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.NotApplicable,
			Justification: triage.MitigationsExist,
			Mitigation:    "the management interface is not exposed on this platform",
			Reasoning:     "Something else stops it.",
			By:            f.proposer, NeedsApproval: true,
		})
		if err != nil {
			t.Fatalf("naming what stops it should have been enough: %v", err)
		}
		if decision.Claim.Mitigation == nil ||
			*decision.Claim.Mitigation != "the management interface is not exposed on this platform" {
			t.Errorf("what stops it was not kept: %v", decision.Claim.Mitigation)
		}
	})
}

func TestNamingWhatStopsItBelongsToThatReasonAlone(t *testing.T) {
	// Meaningless on the others, which are claims about the code rather than
	// about anything standing in front of it. Refused rather than dropped, so
	// nobody records a control they believe is being relied on.
	each(t, func(t *testing.T, f *fixture) {
		_, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath,
			Mitigation:    "a firewall rule nobody asked about",
			Reasoning:     "The parser is never reached.",
			By:            f.proposer, NeedsApproval: true,
		})
		if err == nil {
			t.Fatal("what stops it was accepted alongside a reason that does not claim anything stops it")
		}
	})
}

func TestAVersionTooLongToKeyOnIsRefusedRatherThanShortened(t *testing.T) {
	// The two version columns are part of the index every "does this decision
	// apply here" lookup takes, so they are bounded where the component
	// columns they copy are not. Measured against the reference producer:
	// 6,845 components, longest version 49 characters, nothing over 191.
	//
	// **Refused rather than shortened** is the part that matters. A decision
	// keyed on a truncated version would be compared against the finding's
	// full one and match nothing, so the claim would stand on the record,
	// cover nothing, and say so nowhere. Refused, somebody is told.
	each(t, func(t *testing.T, f *fixture) {
		sprawling := f.at()
		sprawling.ComponentUpstream = strings.Repeat("9", 200)
		_, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
			Place: sprawling, Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath,
			Reasoning:     "The parser is never reached.",
			By:            f.proposer, NeedsApproval: true,
		})
		if err == nil {
			t.Fatal("a decision was keyed on a version the key cannot hold")
		}
		if !strings.Contains(err.Error(), "component") {
			t.Errorf("the refusal does not say which version: %v", err)
		}
		// Nothing was written, so nothing stands covering nothing.
		var standing int
		if err := f.db.NewSelect().Model((*triage.Decision)(nil)).
			Scan(t.Context(), &standing); err == nil && standing != 0 {
			t.Errorf("%d decisions were recorded by a refused proposal", standing)
		}

		// And a version at the limit is still fine, so the check is a bound
		// rather than a refusal of anything unusual.
		atTheLimit := f.at()
		atTheLimit.ComponentUpstream = strings.Repeat("9", 191)
		if _, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
			Place: atTheLimit, Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath,
			Reasoning:     "The parser is never reached.",
			By:            f.proposer, NeedsApproval: true,
		}); err != nil {
			t.Errorf("a version exactly at the limit was refused: %v", err)
		}
	})
}

// A date already past is not a date.
//
// Nothing checked, and the two dates failed in opposite directions. A
// deferral until last year took the place's live key so nobody else could
// decide there, suppressed nothing, and landed in the review queue already
// run out — a work item the tool made for itself. A promise to act by last
// year was worse: the gate asks whether the date is past the deadline the
// work already has, and a date in the past never is, so the promise stood on
// one signature and hid the finding for good.
func TestADateAlreadyPastIsRefused(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		gone := time.Now().UTC().Add(-24 * time.Hour)
		ahead := time.Now().UTC().Add(24 * time.Hour)

		if _, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.Deferred, DeferredUntil: &gone,
			Reasoning: "Not this sprint, last sprint.", By: f.proposer,
		}); err == nil {
			t.Error("a deferral returning on a date already past was recorded")
		}

		// A place of its own, because one live claim per place means a
		// refusal here would otherwise be indistinguishable from the
		// refusal above having left a claim standing.
		elsewhere := f.at()
		elsewhere.PlaceIdentity = "somewhere-else"
		if _, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: elsewhere, Outcome: triage.PatchNeeded, CommittedTo: &gone,
			Reasoning: "Backport landed before it was promised.", By: f.proposer,
		}); err == nil {
			t.Error("work promised for a date already past was recorded")
		}

		// And the same claims, on a date still to come.
		if _, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.Deferred, DeferredUntil: &ahead,
			Reasoning: "Not this sprint.", By: f.proposer,
		}); err != nil {
			t.Errorf("a deferral onto a date still to come was refused: %v", err)
		}
	})
}
