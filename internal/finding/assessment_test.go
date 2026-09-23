// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func TestRatingSomethingWorseTakesEffectAtOnce(t *testing.T) {
	// Nobody needs protecting from being told something is worse than the
	// world says, so raising is not gated — and it has to reach the order,
	// or it is a note nobody acts on.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		mild := found("CVE-2026-RAISE", swss)
		mild.Issue.Severity = "low"
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		before := f.urgency(t, "CVE-2026-RAISE")

		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		claim, err := f.store.Assess(t.Context(), who, f.productID, f.issue(t, "CVE-2026-RAISE"),
			"critical", "Reachable from the network in how we ship it.")
		if err != nil {
			t.Fatal(err)
		}
		if claim.State != finding.AssessmentLive {
			t.Errorf("rating something worse is %s, want it in force at once", claim.State)
		}
		if claim.NeedsApproval {
			t.Error("rating something worse asked for a second person")
		}
		if after := f.urgency(t, "CVE-2026-RAISE"); after <= before {
			t.Errorf("the order did not move: %d then %d", before, after)
		}
		// And the published word is not overwritten by ours.
		published, assessed := f.ratings(t, "CVE-2026-RAISE")
		if published != "low" || assessed != "critical" {
			t.Errorf("ratings are published=%q assessed=%q, want low and critical",
				published, assessed)
		}
	})
}

func TestRatingSomethingMilderWaitsForSomebodyElse(t *testing.T) {
	// The direction that hides things, and it hides more than a position:
	// severity sets the deadline, so a downgrade pushes it out by months.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		bad := found("CVE-2026-LOWER", swss)
		bad.Issue.Severity = "critical"
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}
		before := f.urgency(t, "CVE-2026-LOWER")

		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		claim, err := f.store.Assess(t.Context(), who, f.productID, f.issue(t, "CVE-2026-LOWER"),
			"low", "The affected feature is compiled out of our build.")
		if err != nil {
			t.Fatal(err)
		}
		if claim.State != finding.AssessmentProposed || !claim.NeedsApproval {
			t.Fatalf("a milder rating is %s and needs approval %v, want it waiting",
				claim.State, claim.NeedsApproval)
		}
		if after := f.urgency(t, "CVE-2026-LOWER"); after != before {
			t.Errorf("a claim nobody has agreed to moved the order: %d then %d", before, after)
		}

		// Nobody may agree with themselves.
		if _, err := f.store.Agree(t.Context(), who, claim.ID); err == nil {
			t.Error("the proposer agreed with themselves")
		}

		f.recorded(t, who.ID+1, "somebody-else")
		other := f.holding(t, access.PublicTriage)
		other.ID = who.ID + 1
		if _, err := f.store.Agree(t.Context(), other, claim.ID); err != nil {
			t.Fatal(err)
		}
		if after := f.urgency(t, "CVE-2026-LOWER"); after >= before {
			t.Errorf("agreeing did not move the order down: %d then %d", before, after)
		}
	})
}

func TestReadingAProductDoesNotCarryRatingAnIssueInIt(t *testing.T) {
	// Reading is not arguing. A rating moves this product's deadlines and can
	// take its findings off its working list entirely, and being able to read
	// what it ships is not a reason to be trusted with either — nor is being
	// signed in, which is what stood here before there was a product to hold a
	// role on at all.
	//
	// The product the role has to be held on is pinned by
	// TestRatingAProductAsksForTriageOnThatProduct; this pins that a role is
	// needed at all.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-NOBODY", swss)}); err != nil {
			t.Fatal(err)
		}
		id := f.issue(t, "CVE-2026-NOBODY")

		f.recorded(t, 1, "someone")
		// Signed in, granted reading and nothing else.
		onlooker := f.holding(t, access.PublicRead)
		if _, err := f.store.Assess(t.Context(), onlooker, f.productID, id, "low", "Looks fine to me."); err == nil {
			t.Error("somebody who triages nothing rated an issue")
		}

		// Made by somebody who may, so there is a live claim to act on.
		triager := f.holding(t, access.PublicTriage)
		claim, err := f.store.Assess(t.Context(), triager, f.productID, id, "low", "Compiled out of our build.")
		if err != nil {
			t.Fatal(err)
		}
		f.recorded(t, triager.ID+1, "onlooker")
		onlooker.ID = triager.ID + 1
		if _, err := f.store.Agree(t.Context(), onlooker, claim.ID); err == nil {
			t.Error("somebody who triages nothing agreed to a milder rating")
		}
		if err := f.store.Withdraw(t.Context(), onlooker, claim.ID); err == nil {
			t.Error("somebody who triages nothing took a rating back")
		}
	})
}

func TestWithdrawingTakesThePublishedRatingBack(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		mild := found("CVE-2026-BACK", swss)
		mild.Issue.Severity = "low"
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		before := f.urgency(t, "CVE-2026-BACK")

		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		claim, err := f.store.Assess(t.Context(), who, f.productID, f.issue(t, "CVE-2026-BACK"),
			"critical", "Worse than published.")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.Withdraw(t.Context(), who, claim.ID); err != nil {
			t.Fatal(err)
		}
		if after := f.urgency(t, "CVE-2026-BACK"); after != before {
			t.Errorf("withdrawing did not put the order back: %d then %d", before, after)
		}
		if _, assessed := f.ratings(t, "CVE-2026-BACK"); assessed != "" {
			t.Errorf("a withdrawn rating is still in force: %q", assessed)
		}
	})
}

func TestOneClaimStandsPerIssue(t *testing.T) {
	// A second claim about the same issue is a revision of the first rather
	// than a rival to it, which is the rule decisions already hold to.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		one := found("CVE-2026-ONCE", swss)
		one.Issue.Severity = "medium"
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{one}); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		id := f.issue(t, "CVE-2026-ONCE")
		if _, err := f.store.Assess(t.Context(), who, f.productID, id, "high", "Worse."); err != nil {
			t.Fatal(err)
		}
		second, err := f.store.Assess(t.Context(), who, f.productID, id, "critical", "Worse again.")
		if !errors.Is(err, finding.ErrAlreadyAssessed) {
			t.Errorf("a second claim about one issue got %v (%+v), want ErrAlreadyAssessed", err, second)
		}
	})
}

func TestAWithdrawnAssessmentDoesNotStandInTheWayOfAFreshOne(t *testing.T) {
	// The other half of one claim per issue. A withdrawn claim is history:
	// it stays readable, and it does not stop anybody claiming again.
	// Enforced by a key released on withdrawal rather than by a state
	// check, so what makes room is the same thing that took it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		one := found("CVE-2026-AGAIN", swss)
		one.Issue.Severity = "medium"
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{one}); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		id := f.issue(t, "CVE-2026-AGAIN")

		first, err := f.store.Assess(t.Context(), who, f.productID, id, "high", "Worse.")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.Withdraw(t.Context(), who, first.ID); err != nil {
			t.Fatal(err)
		}
		again, err := f.store.Assess(t.Context(), who, f.productID, id, "critical", "Worse than that.")
		if err != nil {
			t.Fatalf("a withdrawn claim blocked a fresh one: %v", err)
		}
		if again.ID == first.ID {
			t.Error("the fresh claim overwrote the withdrawn one rather than standing beside it")
		}
		// And the withdrawn one is still readable, which is why it was
		// withdrawn rather than deleted.
		if held := f.assessment(t, first.ID); held.State != finding.AssessmentWithdrawn {
			t.Errorf("the withdrawn claim reads as %q", held.State)
		}
	})
}

func TestTwoAssessmentsProposedAtOnceLeaveOneStanding(t *testing.T) {
	// The shape a read-then-write check cannot hold: both proposals read
	// "nothing stands here" before either writes, and both then write.
	// The second is refused by the unique constraint over the issue a
	// live claim is about, which no amount of checking beforehand can
	// substitute for .
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		one := found("CVE-2026-RACE", swss)
		one.Issue.Severity = "medium"
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{one}); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		id := f.issue(t, "CVE-2026-RACE")

		const proposers = 6
		var wg sync.WaitGroup
		results := make([]error, proposers)
		start := make(chan struct{})
		for i := range proposers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, results[i] = f.store.Assess(t.Context(), who, f.productID, id, "high", "Worse.")
			}()
		}
		close(start)
		wg.Wait()

		stood := 0
		for i, err := range results {
			switch {
			case err == nil:
				stood++
			case errors.Is(err, finding.ErrAlreadyAssessed):
			default:
				t.Errorf("proposal %d failed with %v, want ErrAlreadyAssessed", i, err)
			}
		}
		if stood != 1 {
			t.Errorf("%d of %d proposals got through, want exactly one", stood, proposers)
		}
		if live := f.liveAssessments(t, id); live != 1 {
			t.Errorf("%d claims stand about one issue", live)
		}
	})
}

func TestAnApproverIsToldWhatAgreeingTakesOffTheList(t *testing.T) {
	// a downgrade needing a second person gates a downgrade on a second
	// person because it pushes a deadline out. Since the line a deployment
	// triages at exists, a downgrade that crosses a product's triage line
	// does something different in kind: the finding stops being work
	// rather than becoming later work, and no deadline below the line
	// takes its deadline away entirely. Those are two things to agree to
	// and an approver was told neither.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		settings := setting.NewStore(f.db.DB)
		if err := settings.Set(ctx, setting.TriageFloor, "medium"); err != nil {
			t.Fatal(err)
		}

		f.shipped(t, twoConsumers())
		bad := found("CVE-2026-CROSS", libnl)
		bad.Issue.Severity = "high"
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if len(open) != 2 {
			t.Fatalf("opened %d findings", len(open))
		}

		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		id := f.issue(t, "CVE-2026-CROSS")

		// Milder, but still above the line: later work, not no work.
		claim, err := f.store.Assess(ctx, who, f.productID, id, "medium", "Not as bad as published.")
		if err != nil {
			t.Fatal(err)
		}
		would, err := f.store.WhatAgreeingWouldDo(ctx, who, claim.ID)
		if err != nil {
			t.Fatal(err)
		}
		if would.Findings != 2 {
			t.Errorf("agreeing was measured against %+v, want two findings", would)
		}
		if would.OffTheList > 0 {
			t.Errorf("a downgrade that stays above the line reported %d off the list",
				would.OffTheList)
		}

		// Milder still, and now it crosses.
		if err := f.store.Withdraw(ctx, who, claim.ID); err != nil {
			t.Fatal(err)
		}
		crossing, err := f.store.Assess(ctx, who, f.productID, id, "low", "Not worth an afternoon.")
		if err != nil {
			t.Fatal(err)
		}
		would, err = f.store.WhatAgreeingWouldDo(ctx, who, crossing.ID)
		if err != nil {
			t.Fatal(err)
		}
		if would.OffTheList == 0 {
			t.Fatal("a downgrade below the line reported nothing coming off it")
		}
		if would.OffTheList != 2 {
			t.Errorf("it takes %d findings off the list, want 2", would.OffTheList)
		}
	})
}

func TestWhatAgreeingWouldDoCountsOnlyWhatTheReaderMaySee(t *testing.T) {
	// An approver who cannot see a product is not told how many of its
	// findings this would hide. That understates the effect for them, which is
	// the right way for it to be wrong: the alternative discloses a count of
	// undisclosed work.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if err := setting.NewStore(f.db.DB).Set(ctx, setting.TriageFloor, "medium"); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, twoConsumers())
		bad := found("CVE-2026-QUIET", libnl)
		bad.Issue.Severity = "high"
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}
		// One of the two places undisclosed, so a public reader sees a smaller
		// number rather than none — with everything hidden the check below
		// could only fail by returning something it should not.
		one := f.open(t)[0]
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("visibility = ?", access.Private).
			Where("id = ?", one.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		claim, err := f.store.Assess(ctx, who, f.productID, f.issue(t, "CVE-2026-QUIET"),
			"low", "Not worth an afternoon.")
		if err != nil {
			t.Fatal(err)
		}

		public, err := f.store.WhatAgreeingWouldDo(ctx, who, claim.ID)
		if err != nil {
			t.Fatal(err)
		}
		if public.Findings != 1 || public.OffTheList != 1 {
			t.Errorf("a public reader was told %+v, want the one place they may see", public)
		}

		everything := f.holding(t, access.PublicTriage, access.PrivateRead)
		all, err := f.store.WhatAgreeingWouldDo(ctx, everything, claim.ID)
		if err != nil {
			t.Fatal(err)
		}
		if all.Findings != 2 || all.OffTheList != 2 {
			t.Errorf("a reader who may see both was told %+v, want both places", all)
		}
	})
}

func TestAgreeingIsMeasuredOnlyInsideTheRatingsOwnProduct(t *testing.T) {
	// The number an approver is weighing is what *this* rating takes off a
	// working list, and a rating reaches one product. Findings of the same
	// issue in another product are untouched by agreeing, so counting them
	// would inflate the one number in front of somebody — and would describe
	// work this decision does not touch.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		products := catalog.NewStore(f.db.DB)
		if err := setting.NewStore(f.db.DB).Set(ctx, setting.TriageFloor, "medium"); err != nil {
			t.Fatal(err)
		}

		// This product triages from medium, so a high is on its working list.
		f.shipped(t, twoConsumers())
		bad := found("CVE-2026-BOTH", libnl)
		bad.Issue.Severity = "high"
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}

		// And another shipping the same thing, which this rating does not
		// reach.
		elsewhere := f.inAnotherProduct(t, "strict-product")
		if err := products.SetTriageFloor(ctx, f.productOf(t, elsewhere), "medium"); err != nil {
			t.Fatal(err)
		}
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}

		f.recorded(t, 1, "someone")
		// Granted on both products rather than an administrator: since
		// an administrator stopped reading by administering
		// administering is not reading, and what this measures is that
		// holding both still counts only one.
		who := f.holdingIn(t, []int64{f.productID, f.productOf(t, elsewhere)},
			access.PublicTriage, access.PrivateTriage)
		claim, err := f.store.Assess(ctx, who, f.productID, f.issue(t, "CVE-2026-BOTH"),
			"low", "Not worth an afternoon.")
		if err != nil {
			t.Fatal(err)
		}

		would, err := f.store.WhatAgreeingWouldDo(ctx, who, claim.ID)
		if err != nil {
			t.Fatal(err)
		}
		if would.Findings != 2 {
			t.Fatalf("measured against %+v, want the two findings in the rating's own product",
				would)
		}
		if would.OffTheList != 2 {
			t.Errorf("agreeing takes %d findings off the list, want 2 — the two in the other "+
				"product are not reached by this rating at all", would.OffTheList)
		}

		// And agreeing leaves the other product exactly where it was.
		if _, err := f.store.Assess(ctx, f.holdingIn(t,
			[]int64{f.productID, f.productOf(t, elsewhere)}, access.PublicTriage,
			access.PrivateTriage),
			f.productOf(t, elsewhere), f.issue(t, "CVE-2026-BOTH"), "critical",
			"We ship the vulnerable configuration."); err != nil {
			t.Fatal(err)
		}
		if _, rated := f.ratings(t, "CVE-2026-BOTH"); rated != "" {
			t.Errorf("the other product's rating reached this one as %q", rated)
		}
		if _, rated := f.ratingsIn(t, f.productOf(t, elsewhere), "CVE-2026-BOTH"); rated != "critical" {
			t.Errorf("the other product rates it %q, want critical", rated)
		}
	})
}

func TestAnUndisclosedFlawCannotBeRatedByName(t *testing.T) {
	// The leak this closed. an opinion recorded against the issue and the
	// role held anywhere both read "an issue is public knowledge", which
	// holds for a CVE and does not hold for an identifier this deployment
	// minted for a flaw nobody has announced. Anybody who triaged anywhere
	// could name one and be handed the severity recorded against it, and
	// the claim they made then carried that severity to everybody.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		hidden := f.embargoed(t, f.planner(t, access.PublicTriage, access.PrivateTriage))

		// Triage on this very product, and no reading of undisclosed work.
		f.recorded(t, 1, "someone")
		public := f.holding(t, access.PublicTriage)
		_, err := f.store.Assess(t.Context(), public, f.productID, hidden, "low", "Probe.")
		if !errors.Is(err, finding.ErrUnknownIssue) {
			t.Errorf("rating an undisclosed flaw gave %v, want the answer an unused name gives", err)
		}

		// And nothing was written, so the severity did not reach the order.
		if got := f.liveAssessments(t, hidden); got != 0 {
			t.Errorf("%d claims stand about an undisclosed flaw, want 0", got)
		}
	})
}

func TestAClaimAboutAnUndisclosedFlawIsNotListed(t *testing.T) {
	// The read half, which is how the severity reached every credential once
	// one claim existed. The counts beside each row were already narrowed;
	// the row itself was not.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		keeper := f.planner(t, access.PublicTriage, access.PrivateTriage)
		hidden := f.embargoed(t, keeper)
		if _, err := f.store.Assess(t.Context(), keeper, f.productID, hidden, "critical",
			"Worse than it looks."); err != nil {
			t.Fatal(err)
		}

		f.recorded(t, keeper.ID+1, "onlooker")
		reader := f.holding(t, access.PublicRead)
		reader.ID = keeper.ID + 1
		claims, _, _, err := f.store.Assessments(t.Context(), reader, 0, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, claim := range claims {
			if claim.VulnerabilityID == hidden {
				t.Errorf("somebody who may not read the flaw was shown what we say about it: %+v", claim)
			}
		}

		// Whoever may read it still sees it, or the narrowing has hidden the
		// claim from the person who made it.
		mine, _, _, err := f.store.Assessments(t.Context(), keeper, 0, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, claim := range mine {
			if claim.VulnerabilityID == hidden {
				found = true
			}
		}
		if !found {
			t.Error("the claim is hidden from somebody who may read the flaw it is about")
		}
	})
}

func TestAgreeingAndWithdrawingAnswerAsThoughTheClaimWereAbsent(t *testing.T) {
	// A claim identifier is a small number, so "this one is not yours" and
	// "there is no such claim" answering differently is a way to count the
	// undisclosed flaws somebody has an opinion about.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		keeper := f.planner(t, access.PublicTriage, access.PrivateTriage)
		hidden := f.embargoed(t, keeper)
		claim, err := f.store.Assess(t.Context(), keeper, f.productID, hidden, "low",
			"Not reachable in how we ship it.")
		if err != nil {
			t.Fatal(err)
		}

		f.recorded(t, keeper.ID+1, "outsider")
		outsider := f.holding(t, access.PublicTriage)
		outsider.ID = keeper.ID + 1

		_, err = f.store.Agree(t.Context(), outsider, claim.ID)
		if !errors.Is(err, finding.ErrNoSuchAssessment) {
			t.Errorf("agreeing to a claim about an undisclosed flaw gave %v", err)
		}
		if err := f.store.Withdraw(t.Context(), outsider, claim.ID); !errors.Is(err, finding.ErrNoSuchAssessment) {
			t.Errorf("withdrawing a claim about an undisclosed flaw gave %v", err)
		}
		// The same answer a claim nobody ever recorded gives.
		if _, err := f.store.Agree(t.Context(), outsider, claim.ID+9999); !errors.Is(err, finding.ErrNoSuchAssessment) {
			t.Errorf("agreeing to a claim that does not exist gave %v", err)
		}

		// It really is still waiting, so the refusal was a refusal rather than
		// the claim having gone.
		if got := f.assessment(t, claim.ID); got.State != finding.AssessmentProposed {
			t.Errorf("the claim is %s, want it untouched and waiting", got.State)
		}
	})
}

func TestAnIssueThisProductDoesNotCarryCannotBeRatedInIt(t *testing.T) {
	// A rating belongs to a product and says how a component is used there,
	// so an issue the product does not carry is not its to rate. Getting ahead
	// of an issue before it arrives was the deployment-wide shape's, and
	// DESIGN-triage.md records it as given up.
	//
	// Refused in the words a name nobody has used gets, so the route cannot be
	// walked to find out which issues a product ships. And refused by every
	// act on a rating alike: recording one that could then never be withdrawn,
	// agreed to or listed would be the same capability half-built.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		unreached := f.interned(t, "CVE-2026-NOWHERE")

		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		if _, err := f.store.Assess(t.Context(), who, f.productID, unreached, "critical",
			"Rated before it arrives here."); !errors.Is(err, finding.ErrUnknownIssue) {
			t.Errorf("rating an issue this product does not carry answered %v, want the words "+
				"a name nobody has used gets", err)
		}
		if f.liveAssessments(t, unreached) != 0 {
			t.Error("a rating landed on an issue this product does not carry")
		}
	})
}

func TestWhatAgreeingWouldDoStopsAtTheProductsTheReaderHolds(t *testing.T) {
	// Both halves of the narrowing. The visibility half alone admits every
	// disclosed finding in the deployment, so an approver holding one product
	// was told how many findings an issue has in products they hold nothing
	// on — and how many products those are, which is a count of what somebody
	// else ships.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		elsewhere := f.inAnotherProduct(t, "other-product")
		f.shippedTo(t, elsewhere, twoConsumers())

		bad := found("CVE-2026-BOTH", swss)
		bad.Issue.Severity = "critical"
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(t.Context(), elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}

		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage)
		claim, err := f.store.Assess(t.Context(), who, f.productID, f.issue(t, "CVE-2026-BOTH"),
			"low", "Compiled out of our build.")
		if err != nil {
			t.Fatal(err)
		}

		would, err := f.store.WhatAgreeingWouldDo(t.Context(), who, claim.ID)
		if err != nil {
			t.Fatal(err)
		}
		if would.Findings != 1 {
			t.Errorf("an approver holding one product was told this rating covers %d findings,"+
				" want the one in that product — the other product's is neither reached by it"+
				" nor theirs to be told about", would.Findings)
		}
	})
}

func TestRatingAProductAsksForTriageOnThatProduct(t *testing.T) {
	// A rating sets the deadline and can push a finding below the line a
	// product triages at. Asking for triage anywhere, somebody holding one
	// product moves both in a product they cannot see, with nothing in the
	// request naming the product at all.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		bad := found("CVE-2026-ELSE", swss)
		bad.Issue.Severity = "high"
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.inAnotherProduct(t, "other-product")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 1, "someone")
		id := f.issue(t, "CVE-2026-ELSE")

		// Triage on the other product, and reading alone on this one — enough
		// to be told the issue is here, and not enough to move what it costs.
		theirs := access.NewPerson(1, "someone", false, map[int64][]access.Role{
			f.productOf(t, elsewhere): {access.PublicTriage},
			f.productID:               {access.PublicRead},
		}, 101)
		if _, err := f.store.Assess(ctx, theirs, f.productID, id, "critical",
			"Reachable in how they ship it."); !errors.Is(err, access.ErrDenied) {
			t.Fatalf("triage on another product recorded a rating here: %v", err)
		}
		if _, rated := f.ratings(t, "CVE-2026-ELSE"); rated != "" {
			t.Errorf("the rating landed anyway, as %q", rated)
		}

		// And the same person rates their own product, which is the half that
		// has to keep working.
		if _, err := f.store.Assess(ctx, theirs, f.productOf(t, elsewhere), id, "critical",
			"Reachable in how we ship it."); err != nil {
			t.Fatalf("triage on a product could not rate an issue in it: %v", err)
		}
	})
}

func TestAgreeingToARatingAsksForTheRoleOnItsOwnProduct(t *testing.T) {
	// The other half of the same hole. Agreeing is what puts a milder rating
	// into force, so it moves that product's deadlines and its triage line —
	// and a role held somewhere else buys nothing here. Refused in the words a
	// rating that is not there gets, because "you may not agree to this" about
	// a product somebody holds nothing on says the rating is there.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		bad := found("CVE-2026-AGREE", swss)
		bad.Issue.Severity = "high"
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.inAnotherProduct(t, "other-product")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 1, "someone")
		f.recorded(t, 2, "somebody")

		here := access.NewPerson(1, "someone", false,
			map[int64][]access.Role{f.productID: {access.PublicTriage}}, 101)
		claim, err := f.store.Assess(ctx, here, f.productID, f.issue(t, "CVE-2026-AGREE"),
			"low", "Not worth an afternoon.")
		if err != nil {
			t.Fatal(err)
		}
		if !claim.NeedsApproval {
			t.Fatal("a milder rating needed nobody, so this tests nothing")
		}

		// Somebody who approves in another product, and reads this one.
		theirs := access.NewPerson(2, "somebody", false, map[int64][]access.Role{
			f.productOf(t, elsewhere): {access.Approver, access.PublicTriage},
			f.productID:               {access.PublicRead},
		}, 101)
		if _, err := f.store.Agree(ctx, theirs, claim.ID); !errors.Is(err, finding.ErrNoSuchAssessment) {
			t.Fatalf("an approver of another product agreed to this one's rating: %v", err)
		}
		if _, rated := f.ratings(t, "CVE-2026-AGREE"); rated != "" {
			t.Errorf("the rating came into force anyway, as %q", rated)
		}

		// And withdrawing is the same question asked the other way round.
		if err := f.store.Withdraw(ctx, theirs, claim.ID); !errors.Is(err, finding.ErrNoSuchAssessment) {
			t.Errorf("a triager of another product withdrew this one's rating: %v", err)
		}
	})
}

func TestTwoProductsHoldDifferentRatingsOfOneIssue(t *testing.T) {
	// Impossible before: one live claim per issue meant the first product to
	// record one took the answer for everybody, and the second team was told
	// the issue was already assessed. A rating is a judgment about how a
	// component is used, and two products do not use one the same way.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		bad := found("CVE-2026-TWO", swss)
		bad.Issue.Severity = "medium"
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.inAnotherProduct(t, "other-product")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{bad}); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 1, "someone")
		id := f.issue(t, "CVE-2026-TWO")
		who := f.holdingIn(t, []int64{f.productID, f.productOf(t, elsewhere)},
			access.PublicTriage)

		if _, err := f.store.Assess(ctx, who, f.productID, id, "critical",
			"We ship the vulnerable configuration."); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Assess(ctx, who, f.productOf(t, elsewhere), id, "high",
			"We ship it, but not reachable from outside."); err != nil {
			t.Fatalf("a second product could not record its own rating: %v", err)
		}

		if _, rated := f.ratings(t, "CVE-2026-TWO"); rated != "critical" {
			t.Errorf("this product rates it %q, want critical", rated)
		}
		if _, rated := f.ratingsIn(t, f.productOf(t, elsewhere), "CVE-2026-TWO"); rated != "high" {
			t.Errorf("the other product rates it %q, want high", rated)
		}
		// And the published word is untouched by either.
		if published, _ := f.ratings(t, "CVE-2026-TWO"); published != "medium" {
			t.Errorf("the published rating became %q", published)
		}
	})
}

func TestAProductWithNoRatingOfItsOwnReadsThePublishedOne(t *testing.T) {
	// Nothing inherits. A rating arriving in a product from a team that cannot
	// see it is exactly what a per-product rating removes, so it is not
	// reintroduced as a default: a product nobody has looked at reads what the
	// world says until somebody there does.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		mild := found("CVE-2026-NONE", libnl)
		mild.Issue.Severity = "low"
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.inAnotherProduct(t, "other-product")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{mild}); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 1, "someone")
		who := f.holdingIn(t, []int64{f.productID, f.productOf(t, elsewhere)},
			access.PublicTriage)
		if _, err := f.store.Assess(ctx, who, f.productID, f.issue(t, "CVE-2026-NONE"),
			"critical", "Reachable in how we ship it."); err != nil {
			t.Fatal(err)
		}

		// The list in the product that rated it, and the list in the one that
		// did not, asked the same way.
		rated, _, err := f.store.Groups(ctx, who, f.scope, 50, 0,
			finding.Filter{MinSeverity: "high"})
		if err != nil {
			t.Fatal(err)
		}
		if len(rated) != 1 || rated[0].Severity != "critical" {
			t.Fatalf("the product that rated it lists %d rows: %+v", len(rated), rated)
		}
		otherID := f.productOf(t, elsewhere)
		theirs, _, err := f.store.Groups(ctx, who, finding.Scope{ProductID: &otherID}, 50, 0,
			finding.Filter{MinSeverity: "high"})
		if err != nil {
			t.Fatal(err)
		}
		if len(theirs) != 0 {
			t.Errorf("a rating made in one product raised a finding in another: %+v", theirs)
		}
	})
}

func TestTheRatingsListIsPagedAndSaysHowManyThereAre(t *testing.T) {
	// Capped at two hundred with no offset and no total, a deployment past
	// that could not read the rest through the API at all — and the screen
	// showed a subset and reported it as the list. Every comparable list in
	// the package is paged and totalled; this was the one that was not.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		keeper := f.planner(t, access.PublicTriage, access.PrivateTriage)
		for range 5 {
			id := f.embargoed(t, keeper)
			if _, err := f.store.Assess(ctx, keeper, f.productID, id, "medium",
				"The affected routine is not built here."); err != nil {
				t.Fatal(err)
			}
		}

		first, _, total, err := f.store.Assessments(ctx, keeper, 0, "", 2, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 5 {
			t.Errorf("the list says there are %d ratings, want the five recorded", total)
		}
		if len(first) != 2 {
			t.Fatalf("a page of two came back with %d", len(first))
		}
		// The total is counted over the same narrowing rather than summed
		// from the page, which is the difference between "five" and "two".
		later, _, again, err := f.store.Assessments(ctx, keeper, 0, "", 2, 4)
		if err != nil {
			t.Fatal(err)
		}
		if again != total {
			t.Errorf("the total changed with the page, from %d to %d", total, again)
		}
		if len(later) != 1 {
			t.Fatalf("the last page came back with %d, want the one remaining", len(later))
		}
		if later[0].ID == first[0].ID {
			t.Error("skipping four rows answered with the first of them")
		}
	})
}
