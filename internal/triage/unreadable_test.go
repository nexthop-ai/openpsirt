// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// A read that fails is a fault, never an answer that the row is not there.
//
// "Not yours" and "not there" are one answer on purpose, so that guessing an
// identifier says nothing. A read the database could not make is neither: it
// is answered as a fault the caller logs, and inside a transaction it is left
// for the retry helper to judge. Each act here has its first read of the row
// it names made to fail, and must come back with something other than the
// refusal.
func TestAReadThatFailsIsNotAnsweredAsAbsent(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.agreed(t, f.at())
		said, err := f.store.Say(ctx, f.triager, claimed.ClaimID, "Checked against the build log.")
		if err != nil {
			t.Fatal(err)
		}
		// Recorded after the claim was agreed, which it takes back; nothing
		// here needs the agreement to stand, only the rows to be there.
		record, _ := f.exploited(t)
		note, err := f.store.NoteOn(ctx, f.triager, f.product, f.issue, "Upstream has a patch queued.")
		if err != nil {
			t.Fatal(err)
		}
		another := f.at()
		another.PlaceIdentity = "under-a"

		fault := new(dbtest.Fault)
		f.hook(fault)

		for _, c := range []struct {
			name, table string
			refusal     error
			act         func(context.Context) error
		}{
			{"reading a claim whole", "claim", triage.ErrNotTheirs,
				func(ctx context.Context) error {
					_, err := f.store.Whole(ctx, f.triager, claimed.ClaimID)
					return err
				}},
			{"reading a claim's revisions", "claim", triage.ErrNotTheirs,
				func(ctx context.Context) error {
					_, err := f.store.Revisions(ctx, f.triager, claimed.ClaimID)
					return err
				}},
			{"reading a decision", "decision", triage.ErrNotTheirs,
				func(ctx context.Context) error {
					_, _, err := f.store.Read(ctx, f.triager, claimed.ID)
					return err
				}},
			{"re-making a decision", "decision", triage.ErrNotTheirs,
				func(ctx context.Context) error {
					_, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
						PreviousID: claimed.ID, Place: f.at(),
						Reasoning: "Still true.", By: f.proposer,
					})
					return err
				}},
			{"re-making a claim", "claim", triage.ErrNotTheirs,
				func(ctx context.Context) error {
					_, err := f.store.ReaffirmClaim(ctx, f.triager, triage.ReaffirmingClaim{
						PreviousClaimID: claimed.ClaimID, Reasoning: "Still true.",
						By: f.proposer, Bounds: triage.DefaultBounds(),
					})
					return err
				}},
			{"carrying a claim to another place", "claim", triage.ErrNotTheirs,
				func(ctx context.Context) error {
					_, err := f.store.Extend(ctx, f.triager, claimed.ClaimID, []triage.Proposal{{
						Place: another, Outcome: triage.NotApplicable,
						Justification: triage.CodeNotInExecutePath,
						Reasoning:     "The same code path.", By: f.proposer, NeedsApproval: true,
					}})
					return err
				}},
			{"changing a comment", "claim_comment", triage.ErrNotTheirs,
				func(ctx context.Context) error {
					_, err := f.store.Reword(ctx, f.triager, said.ID, "Checked twice.")
					return err
				}},
			{"reading what a comment said before", "claim_comment", triage.ErrNotTheirs,
				func(ctx context.Context) error {
					_, err := f.store.Earlier(ctx, f.triager, said.ID)
					return err
				}},
			{"reading what a note said before", "issue_note", triage.ErrNoSuchNote,
				func(ctx context.Context) error {
					_, err := f.store.EarlierNote(ctx, f.triager, note.ID)
					return err
				}},
			{"clearing a record of being exploited", "exploited_here",
				triage.ErrNoSuchExploitedHere,
				func(ctx context.Context) error {
					return f.store.ClearExploitedHere(ctx, f.triager, record.ID, "It was a test harness.")
				}},
		} {
			t.Run(c.name, func(t *testing.T) {
				fault.Arm("SELECT", c.table)
				err := c.act(ctx)
				if !fault.Disarm() {
					t.Fatalf("no read of %s was made, so this tests nothing", c.table)
				}
				if err == nil {
					t.Fatal("a read that failed was answered as a success")
				}
				if errors.Is(err, c.refusal) {
					t.Errorf("a read that failed was answered as the row not being there: %v", err)
				}
				if !errors.Is(err, context.Canceled) {
					t.Errorf("the failure does not carry its cause: %v", err)
				}
			})
		}
	})
}
