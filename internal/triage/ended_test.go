// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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
