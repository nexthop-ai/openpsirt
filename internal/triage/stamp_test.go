// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// stampOf is the stamp a decision holds, zero where it has no row.
func stampOf(t *testing.T, f *fixture, decisionID int64) int {
	t.Helper()
	var stamp int
	if err := f.db.DB.NewSelect().TableExpr(`"decision_stamp" AS "cs"`).
		ColumnExpr(`COALESCE(MAX("cs"."stamp"), 0)`).Where(`"cs"."decision_id" = ?`, decisionID).Scan(t.Context(), &stamp); err != nil {
		t.Fatal(err)
	}
	return stamp
}

// A writer holding the stamp a decision was read with changes it, and a writer
// holding the stamp from before another's change matches nothing and is told
// it lost a race the retry helper takes again.
func TestADecisionRestampedFromAStaleStampIsALostRace(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		decisionID := f.decisions(t, f.at()).DecisionID
		read := stampOf(t, f, decisionID)
		if err := triage.Restamp(ctx, f.db.DB, decisionID, read); err != nil {
			t.Fatalf("restamping from the stamp read answered %v", err)
		}
		if got := stampOf(t, f, decisionID); got == read {
			t.Fatalf("the stamp is %d after a restamp; want it changed", got)
		}
		err := triage.Restamp(ctx, f.db.DB, decisionID, read)
		if !errors.Is(err, database.ErrGoAgain) || !database.WorthRetrying(err) {
			t.Fatalf("restamping from a stale stamp answered %v; want a lost race to take again", err)
		}
	})
}

// A decision nobody has stamped reads as zero, and two writers that both read
// that are one first stamp and one lost race: the second finds the row the
// first made.
func TestTwoFirstStampsOfADecisionAreOneLostRace(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		decisionID := f.decisions(t, f.at()).DecisionID
		if got := stampOf(t, f, decisionID); got != 0 {
			t.Fatalf("a decision nobody wrote to holds the stamp %d; want zero", got)
		}
		if err := triage.Restamp(ctx, f.db.DB, decisionID, 0); err != nil {
			t.Fatalf("the first stamp answered %v", err)
		}
		err := triage.Restamp(ctx, f.db.DB, decisionID, 0)
		if !errors.Is(err, database.ErrGoAgain) || !database.WorthRetrying(err) {
			t.Fatalf("a second first stamp answered %v; want a lost race to take again", err)
		}
		if got := stampOf(t, f, decisionID); got != 1 {
			t.Errorf("the stamp is %d after one first stamp; want 1", got)
		}
	})
}

// A stamp past the first is matched on the value read, as the first is.
func TestALaterStampFromAStaleValueIsALostRace(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		decisionID := f.decisions(t, f.at()).DecisionID
		if err := triage.Restamp(ctx, f.db.DB, decisionID, 0); err != nil {
			t.Fatalf("the first stamp answered %v", err)
		}
		if err := triage.Restamp(ctx, f.db.DB, decisionID, 1); err != nil {
			t.Fatalf("restamping from the stamp read answered %v", err)
		}
		if got := stampOf(t, f, decisionID); got != 2 {
			t.Fatalf("the stamp is %d after two stamps; want 2", got)
		}
		err := triage.Restamp(ctx, f.db.DB, decisionID, 1)
		if !errors.Is(err, database.ErrGoAgain) || !database.WorthRetrying(err) {
			t.Fatalf("restamping from a stale stamp answered %v; want a lost race to take again", err)
		}
	})
}

// Every write to a decision that refuses a decision about a lead handed off changes
// its stamp, so a hand-off resting on the decision cannot commit beside it.
func TestEveryWriteToADecisionChangesItsStamp(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		for _, c := range []struct {
			act   string
			write func(decisionID int64) error
		}{
			{"revising it", func(id int64) error {
				_, err := f.store.Revise(ctx, f.triager, id, "The parser is unreachable from every entry point.")
				return err
			}},
			{"sending it back", func(id int64) error {
				_, err := f.store.SendBackDecision(ctx, f.reviewer, id, "Say which entry points.")
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
			decisionID := f.decisions(t, f.at()).DecisionID
			before := stampOf(t, f, decisionID)
			if err := c.write(decisionID); err != nil {
				t.Fatalf("%s answered %v", c.act, err)
			}
			if got := stampOf(t, f, decisionID); got == before {
				t.Errorf("%s left the stamp at %d", c.act, got)
			}
			if _, err := f.store.Withdraw(ctx, f.triager, decisionID); err != nil && c.act != "withdrawing it" {
				t.Fatalf("clearing the occurrence after %s answered %v", c.act, err)
			}
		}
	})
}
