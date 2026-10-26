// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// stampOf is the stamp a claim holds, zero where it has no row.
func stampOf(t *testing.T, f *fixture, claimID int64) int {
	t.Helper()
	var stamp int
	if err := f.db.DB.NewSelect().TableExpr(`"claim_stamp" AS "cs"`).
		ColumnExpr(`COALESCE(MAX("cs"."stamp"), 0)`).Where(`"cs"."claim_id" = ?`, claimID).Scan(t.Context(), &stamp); err != nil {
		t.Fatal(err)
	}
	return stamp
}

// A writer holding the stamp a claim was read with changes it, and a writer
// holding the stamp from before another's change matches nothing and is told
// it lost a race the retry helper takes again.
func TestAClaimRestampedFromAStaleStampIsALostRace(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimID := f.claims(t, f.at()).ClaimID
		read := stampOf(t, f, claimID)
		if err := triage.Restamp(ctx, f.db.DB, claimID, read); err != nil {
			t.Fatalf("restamping from the stamp read answered %v", err)
		}
		if got := stampOf(t, f, claimID); got == read {
			t.Fatalf("the stamp is %d after a restamp; want it changed", got)
		}
		err := triage.Restamp(ctx, f.db.DB, claimID, read)
		if !errors.Is(err, database.ErrGoAgain) || !database.WorthRetrying(err) {
			t.Fatalf("restamping from a stale stamp answered %v; want a lost race to take again", err)
		}
	})
}

// A claim nobody has stamped reads as zero, and two writers that both read
// that are one first stamp and one lost race: the second finds the row the
// first made.
func TestTwoFirstStampsOfAClaimAreOneLostRace(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimID := f.claims(t, f.at()).ClaimID
		if got := stampOf(t, f, claimID); got != 0 {
			t.Fatalf("a claim nobody wrote to holds the stamp %d; want zero", got)
		}
		if err := triage.Restamp(ctx, f.db.DB, claimID, 0); err != nil {
			t.Fatalf("the first stamp answered %v", err)
		}
		err := triage.Restamp(ctx, f.db.DB, claimID, 0)
		if !errors.Is(err, database.ErrGoAgain) || !database.WorthRetrying(err) {
			t.Fatalf("a second first stamp answered %v; want a lost race to take again", err)
		}
		if got := stampOf(t, f, claimID); got != 1 {
			t.Errorf("the stamp is %d after one first stamp; want 1", got)
		}
	})
}

// A stamp past the first is matched on the value read, as the first is.
func TestALaterStampFromAStaleValueIsALostRace(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimID := f.claims(t, f.at()).ClaimID
		if err := triage.Restamp(ctx, f.db.DB, claimID, 0); err != nil {
			t.Fatalf("the first stamp answered %v", err)
		}
		if err := triage.Restamp(ctx, f.db.DB, claimID, 1); err != nil {
			t.Fatalf("restamping from the stamp read answered %v", err)
		}
		if got := stampOf(t, f, claimID); got != 2 {
			t.Fatalf("the stamp is %d after two stamps; want 2", got)
		}
		err := triage.Restamp(ctx, f.db.DB, claimID, 1)
		if !errors.Is(err, database.ErrGoAgain) || !database.WorthRetrying(err) {
			t.Fatalf("restamping from a stale stamp answered %v; want a lost race to take again", err)
		}
	})
}

// Every write to a claim that refuses a claim about a lead handed off changes
// its stamp, so a hand-off resting on the claim cannot commit beside it.
func TestEveryWriteToAClaimChangesItsStamp(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		for _, c := range []struct {
			act   string
			write func(claimID int64) error
		}{
			{"revising it", func(id int64) error {
				_, err := f.store.Revise(ctx, f.triager, id, "The parser is unreachable from every entry point.")
				return err
			}},
			{"sending it back", func(id int64) error {
				_, err := f.store.SendBackClaim(ctx, f.reviewer, id, "Say which entry points.")
				return err
			}},
			{"agreeing to it", func(id int64) error { return agreeTo(ctx, f.store, f.reviewer, id, "") }},
			{"undoing the agreement", func(id int64) error {
				if err := agreeTo(ctx, f.store, f.reviewer, id, "afternoon"); err != nil {
					return err
				}
				before := stampOf(t, f, id)
				undone, err := f.store.UndoBatch(ctx, f.reviewer, "afternoon")
				if err == nil && undone.Rows == 0 {
					t.Errorf("undoing the batch returned nothing to waiting, so it checks nothing")
				}
				if got := stampOf(t, f, id); got == before {
					t.Errorf("undoing the agreement left the stamp at %d", got)
				}
				return err
			}},
			{"withdrawing it", func(id int64) error { _, err := f.store.Withdraw(ctx, f.triager, id); return err }},
		} {
			claimID := f.claims(t, f.at()).ClaimID
			before := stampOf(t, f, claimID)
			if err := c.write(claimID); err != nil {
				t.Fatalf("%s answered %v", c.act, err)
			}
			if got := stampOf(t, f, claimID); got == before {
				t.Errorf("%s left the stamp at %d", c.act, got)
			}
			if _, err := f.store.Withdraw(ctx, f.triager, claimID); err != nil && c.act != "withdrawing it" {
				t.Fatalf("clearing the place after %s answered %v", c.act, err)
			}
		}
	})
}
