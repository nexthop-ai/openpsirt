// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// ends puts one row of a claim where a lapse leaves it: ended at a moment,
// holding no live key.
func (f *fixture) ends(t *testing.T, decisionID int64, at time.Time) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Model((*triage.Decision)(nil)).
		Set("state = ?", triage.LapsedState).
		Set("live_key = ?", nil).
		Set("ended_at = ?", at).
		Where("id = ?", decisionID).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// row reads one decision back as stored.
func (f *fixture) row(t *testing.T, id int64) triage.Decision {
	t.Helper()
	var row triage.Decision
	if err := f.db.DB.NewSelect().Model(&row).Where("de.id = ?", id).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return row
}

func TestUndoingAnApprovalLeavesARowThatHasEndedAlone(t *testing.T) {
	// A lapse leaves the approval standing, so the claim is still in the
	// batch. Returned to waiting, the lapsed row would be a proposal holding
	// no live key, which nothing stops a contradicting claim from joining.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		made := f.claimsMany(t, f.places("under-a", "under-b"))
		if err := agreeTo(ctx, f.store, f.reviewer, made[0].ClaimID, "one-afternoon"); err != nil {
			t.Fatal(err)
		}
		ended := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		f.ends(t, made[1].ID, ended)

		undone, err := f.store.UndoBatch(ctx, f.reviewer, "one-afternoon")
		if err != nil {
			t.Fatal(err)
		}
		if undone.Rows != 1 {
			t.Errorf("%d rows returned to waiting, want the one still standing", undone.Rows)
		}
		if got := f.row(t, made[0].ID); got.State != triage.Proposed {
			t.Errorf("the standing row is %q, want it waiting again", got.State)
		}
		lapsed := f.row(t, made[1].ID)
		if lapsed.State != triage.LapsedState || lapsed.LiveKey != nil {
			t.Errorf("the lapsed row became %q holding key %v", lapsed.State, lapsed.LiveKey)
		}
	})
}

func TestRevivingAClaimWhosePlaceIsTakenNamesTheClaimStandingThere(t *testing.T) {
	// Revising a withdrawn claim retakes its places. Where another claim
	// holds one since, the refusal is the one proposing there gets.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := f.claims(t, f.at())
		if err := f.store.Withdraw(ctx, f.triager, first.ClaimID); err != nil {
			t.Fatal(err)
		}
		standing := f.claims(t, f.at())

		_, err := f.store.Revise(ctx, f.triager, first.ClaimID, "On reflection it holds.")
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("reviving onto a taken place answered %v, want it already decided", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("decision %d ", standing.ID)) {
			t.Errorf("the refusal %q does not name decision %d", err, standing.ID)
		}
	})
}

func TestRevivingAPartlyEndedClaimNamesTheClaimAtTheTakenPlace(t *testing.T) {
	// One place of two lapsed and another claim took it. The refusal names
	// that claim's row, never the reviving claim's own row still standing at
	// the other place.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		made := f.claimsMany(t, f.places("under-a", "under-b"))
		f.ends(t, made[1].ID, time.Now().UTC().Truncate(time.Microsecond))
		standing := f.claims(t, f.places("under-b")[0])

		_, err := f.store.Revise(ctx, f.triager, made[0].ClaimID, "On reflection it holds.")
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("reviving onto a taken place answered %v, want it already decided", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("decision %d ", standing.ID)) {
			t.Errorf("the refusal %q does not name decision %d", err, standing.ID)
		}
	})
}

func TestMovingAWithdrawnPromiseOntoATakenPlaceNamesTheClaimThere(t *testing.T) {
	// Changing a promise revives it, so it meets the same refusal a revision
	// does, and names the claim standing at the place the same way.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		by := time.Now().UTC().AddDate(0, 0, 30).Truncate(time.Second)
		promised, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.UpgradeNeeded, UpgradeTo: "2.0", CommittedTo: &by,
			Reasoning: "Moving to the release that drops the parser.", By: f.proposer,
			NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.Withdraw(ctx, f.triager, promised.ClaimID); err != nil {
			t.Fatal(err)
		}
		standing := f.claims(t, f.at())

		_, _, err = f.store.Repromise(ctx, f.triager, promised.ClaimID, "2.1", by,
			"The release moved.")
		if !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Fatalf("moving a promise onto a taken place answered %v, want it already decided", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("decision %d ", standing.ID)) {
			t.Errorf("the refusal %q does not name decision %d", err, standing.ID)
		}
	})
}

func TestAProposerWhoseRowsSpanSeveralReadsIsToldOnce(t *testing.T) {
	// A sweep lapsing more rows than one read names reads who to tell in
	// pieces. One person is one notice however the rows fall.
	each(t, func(t *testing.T, f *fixture) {
		made := f.claimsMany(t, f.places("under-a", "under-b", "under-c"))
		ids := []int64{made[2].ID, made[0].ID, made[1].ID}
		told, err := f.store.ProposersOfAll(t.Context(), ids, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(told) != 1 {
			t.Fatalf("one proposer came back as %d entries: %+v", len(told), told)
		}
		if told[0].Rows != 3 || told[0].DecisionID != made[0].ID {
			t.Errorf("told %+v, want three rows represented by decision %d", told[0], made[0].ID)
		}
	})
}

func TestASimilarClaimCountsEveryIssueItCovers(t *testing.T) {
	// A bulk claim offered as similar covers far more rows than one read
	// returns. Its issue count is over all of them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		other := f.at()
		other.VulnerabilityID = f.secondIssue(t)
		other.PlaceIdentity = "under-b"
		agreed := f.claimsMany(t, []triage.Place{other})
		if _, err := f.store.ApproveClaim(ctx, f.reviewer, agreed[0].ClaimID, "", nil, ""); err != nil {
			t.Fatal(err)
		}
		// Many more rows of the same claim about the second issue, then one
		// about a third, written last.
		template := f.row(t, agreed[0].ID)
		filler := make([]triage.Decision, 0, 601)
		for i := range 600 {
			row := template
			row.ID = 0
			row.LiveKey = nil
			row.PlaceIdentity = fmt.Sprintf("filler-%03d", i)
			filler = append(filler, row)
		}
		last := template
		last.ID, last.LiveKey = 0, nil
		last.PlaceIdentity = "filler-last"
		last.VulnerabilityID = f.anotherIssue(t, "CVE-2026-3")
		filler = append(filler, last)
		if _, err := f.db.DB.NewInsert().Model(&filler).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		similar, err := f.store.SimilarAt(ctx, f.reviewer, f.product, f.issue,
			[]string{"under-b"})
		if err != nil || len(similar) != 1 {
			t.Fatalf("the bulk claim is not offered: %+v (%v)", similar, err)
		}
		if similar[0].Issues != 2 {
			t.Errorf("a claim over two issues is offered as covering %d", similar[0].Issues)
		}
	})
}

func TestWhatAPersonGotThroughIsCountedInClaims(t *testing.T) {
	// One argument over many places is one piece of work, whether it was
	// made, agreed to or taken back. Counted per row, a bulk proposer reads
	// as forty-five times busier than the approver of the same claim.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		kept := f.claimsMany(t, f.places("under-a", "under-b", "under-c"))
		if err := agreeTo(ctx, f.store, f.reviewer, kept[0].ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		dropped := f.claimsMany(t, f.places("under-d", "under-e"))
		if err := f.store.Withdraw(ctx, f.triager, dropped[0].ClaimID); err != nil {
			t.Fatal(err)
		}

		measured, err := f.store.Measure(ctx, f.reviewer, triage.Measuring{}, time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]triage.Worked{}
		for _, one := range measured.Throughput {
			got[one.Person] = one
		}
		if p := got["proposer"]; p.Proposed != 2 || p.Withdrawn != 1 {
			t.Errorf("the proposer made %d claims and withdrew %d, want 2 and 1", p.Proposed, p.Withdrawn)
		}
		if a := got["approver"]; a.Approved != 1 {
			t.Errorf("the approver agreed to %d claims, want 1", a.Approved)
		}
	})
}

func TestAClaimThatGrewIsReportedHoweverManyWereAgreedToBeforeIt(t *testing.T) {
	// The cap applies to the claims that grew, worst first. Taken off the
	// oldest agreements, a claim agreed to after them never appears.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.build(t, f.product, "2026.03")
		libfoo := f.component(t, "libfoo", "1.2.3")
		for _, place := range []string{"place-a", "place-b"} {
			at := f.at()
			at.PlaceIdentity = place
			at.ConsumerUpstream = ""
			f.agreed(t, at)
		}
		// The newer claim now reaches a finding nobody agreed to it covering.
		f.finds(t, in, libfoo, "place-b", access.Public)

		scrutiny, err := f.store.Scrutinize(ctx, f.reviewer, nil, time.Time{}, time.Time{}, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(scrutiny.Grew) != 1 || scrutiny.Grew[0].CoversNow != 1 {
			t.Fatalf("what grew reads %+v, want the claim at place-b covering one", scrutiny.Grew)
		}
	})
}

func TestAWithdrawnClaimReachesNothing(t *testing.T) {
	// What a claim covers now is what it suppresses. Taken back, it
	// suppresses nothing, however well its versions still match.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.build(t, f.product, "2026.03")
		at := f.at()
		at.PlaceIdentity = "place-of-libfoo"
		at.ConsumerUpstream = ""
		f.finds(t, in, f.component(t, "libfoo", "1.2.3"), "place-of-libfoo", access.Public)
		made := f.claims(t, at)

		before, err := f.store.Whole(ctx, f.triager, made.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if before.Reach.Findings != 1 || len(before.Builds) != 1 {
			t.Fatalf("a standing claim reaches %+v in %v, want one finding in one build",
				before.Reach, before.Builds)
		}
		if err := f.store.Withdraw(ctx, f.triager, made.ClaimID); err != nil {
			t.Fatal(err)
		}
		after, err := f.store.Whole(ctx, f.triager, made.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if after.Reach.Findings != 0 || len(after.Builds) != 0 {
			t.Errorf("a withdrawn claim reaches %+v in %v, want nothing", after.Reach, after.Builds)
		}
	})
}

func TestAWithdrawnClaimReportsWhatItReachedWhenItWasWithdrawn(t *testing.T) {
	// Taken back, a claim reaches nothing now. What it reached then is the
	// builds holding one of its places open at that moment: a finding closed
	// before it and one opened after it are not part of it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		at := f.at()
		at.PlaceIdentity = "place-of-libfoo"
		at.ConsumerUpstream = ""
		libfoo := f.component(t, "libfoo", "1.2.3")

		held := f.build(t, f.product, "2026.03")
		f.finds(t, held, libfoo, at.PlaceIdentity, access.Public)
		gone := f.build(t, f.product, "2026.02")
		closed := f.finds(t, gone, libfoo, at.PlaceIdentity, access.Public)
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("closed_at = ?", time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)).
			Set("closed_run_id = ?", gone.run).
			Where("id = ?", closed).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		made := f.claims(t, at)
		if err := f.store.Withdraw(ctx, f.triager, made.ClaimID); err != nil {
			t.Fatal(err)
		}
		later := f.build(t, f.product, "2026.04")
		f.opened(t, f.finds(t, later, libfoo, at.PlaceIdentity, access.Public),
			time.Now().UTC().Add(time.Hour))

		whole, err := f.store.Whole(ctx, f.triager, made.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if whole.Reach.Findings != 0 || len(whole.Builds) != 0 {
			t.Errorf("a withdrawn claim reaches %+v in %v now, want nothing", whole.Reach, whole.Builds)
		}
		if len(whole.Ended) != 1 {
			t.Fatalf("ended parts %+v, want the withdrawn one alone", whole.Ended)
		}
		part := whole.Ended[0]
		if part.State != triage.Withdrawn || part.Rows != 1 || part.Places != 1 {
			t.Errorf("the withdrawn part is %+v, want one row at one place", part)
		}
		if len(part.Builds) != 1 || !strings.HasPrefix(part.Builds[0], "2026.03") {
			t.Errorf("it reached %v when withdrawn, want 2026.03 alone", part.Builds)
		}
		if part.At.IsZero() {
			t.Error("the withdrawn part carries no moment")
		}
	})
}

func TestAPartlyLapsedClaimReportsTheLapsedPartApart(t *testing.T) {
	// One place of two lapsed. The claim still reaches the other now, and
	// what the lapsed one reached when it lapsed is reported on its own.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		libfoo := f.component(t, "libfoo", "1.2.3")
		in := f.build(t, f.product, "2026.03")
		f.finds(t, in, libfoo, "under-a", access.Public)
		made := f.claimsMany(t, f.places("under-a", "under-b"))
		f.ends(t, made[0].ID, time.Now().UTC().Truncate(time.Microsecond))

		whole, err := f.store.Whole(ctx, f.triager, made[0].ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if len(whole.Ended) != 1 {
			t.Fatalf("ended parts %+v, want the lapsed one alone", whole.Ended)
		}
		part := whole.Ended[0]
		if part.State != triage.LapsedState || part.Rows != 1 || part.Places != 1 {
			t.Errorf("the lapsed part is %+v, want one row at one place", part)
		}
		if len(part.Builds) != 1 || !strings.HasPrefix(part.Builds[0], "2026.03") {
			t.Errorf("it reached %v when it lapsed, want 2026.03 alone", part.Builds)
		}
	})
}

func TestAClaimNothingEndedReportsNoEndedPart(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		made := f.claims(t, f.at())
		whole, err := f.store.Whole(t.Context(), f.triager, made.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if len(whole.Ended) != 0 {
			t.Errorf("a standing claim reports ended parts %+v", whole.Ended)
		}
	})
}

func TestWithdrawingAClaimLeavesARowThatHasEndedAsItEnded(t *testing.T) {
	// A lapse records when and why a row stopped applying. Withdrawing the
	// claim afterwards is about the rows still standing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		made := f.claimsMany(t, f.places("under-a", "under-b"))
		ended := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
		f.ends(t, made[1].ID, ended)

		if err := f.store.Withdraw(ctx, f.triager, made[0].ClaimID); err != nil {
			t.Fatal(err)
		}
		if got := f.row(t, made[0].ID); got.State != triage.Withdrawn {
			t.Errorf("the standing row is %q, want withdrawn", got.State)
		}
		lapsed := f.row(t, made[1].ID)
		if lapsed.State != triage.LapsedState {
			t.Errorf("the lapsed row became %q, want it still lapsed", lapsed.State)
		}
		if lapsed.EndedAt == nil || !lapsed.EndedAt.Equal(ended) {
			t.Errorf("the lapsed row ended %v, want %v", lapsed.EndedAt, ended)
		}
	})
}
