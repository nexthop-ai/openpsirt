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
