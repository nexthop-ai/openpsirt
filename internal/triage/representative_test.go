// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// mixed is a decision of three rows whose middle one is undisclosed, with both
// people able to argue about it. The earliest row is public, so a
// representative chosen by identifier is the wrong one.
func (f *fixture) mixed(t *testing.T) []*triage.DecisionOccurrence {
	t.Helper()
	ctx := t.Context()
	rights := access.NewStore(f.db.DB)
	for _, who := range []int64{f.proposer, f.approver} {
		if err := rights.GrantRole(ctx, who, f.product, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
	}
	for _, who := range []*access.Subject{&f.triager, &f.reviewer} {
		resolved, err := rights.Resolve(ctx, who.Identity)
		if err != nil {
			t.Fatal(err)
		}
		*who = resolved
	}
	made := f.decisionsMany(t, f.occurrences("under-a", "under-b", "under-c"))
	if _, err := f.db.DB.NewUpdate().Model((*triage.DecisionOccurrence)(nil)).
		Set(`"visibility" = ?`, access.Private).
		Where(`"id" = ?`, made[1].ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return made
}

func TestANoticeAboutADecisionNamesItsMostWithheldRow(t *testing.T) {
	// A notice withheld as undisclosed is read only where its product's
	// undisclosed work is, so the row it is stored against is the one that
	// made it withheld.
	t.Run("whoever proposed rows, in one read and across several", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			made := f.mixed(t)
			ids := []int64{made[0].ID, made[1].ID, made[2].ID}
			for _, chunk := range []int{1, len(ids)} {
				told, err := f.store.ProposersOfAll(t.Context(), ids, chunk)
				if err != nil {
					t.Fatal(err)
				}
				if len(told) != 1 || told[0].DecisionOccurrenceID != made[1].ID || !told[0].Undisclosed {
					t.Errorf("read %d at a time, told %+v; want one undisclosed entry represented by %d",
						chunk, told, made[1].ID)
				}
			}
		})
	})
	t.Run("a decision sent back", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			made := f.mixed(t)
			back, err := f.store.SendBackDecision(t.Context(), f.reviewer, made[0].DecisionID, "Say which file.")
			if err != nil {
				t.Fatal(err)
			}
			if back.DecisionOccurrence.ID != made[1].ID || !back.Undisclosed {
				t.Errorf("sent back represented by %d, undisclosed %v; want %d, undisclosed",
					back.DecisionOccurrence.ID, back.Undisclosed, made[1].ID)
			}
		})
	})
	t.Run("an agreement a revision withdrew", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			ctx := t.Context()
			made := f.mixed(t)
			if _, err := f.store.ApproveDecision(ctx, f.reviewer, made[0].DecisionID, "", nil, ""); err != nil {
				t.Fatal(err)
			}
			revised, err := f.store.Revise(ctx, f.triager, made[0].DecisionID, "Checked the other file too.")
			if err != nil {
				t.Fatal(err)
			}
			if len(revised.Withdrawn) != 1 || revised.Withdrawn[0].DecisionOccurrenceID != made[1].ID ||
				!revised.Withdrawn[0].Undisclosed {
				t.Errorf("withdrew %+v; want one undisclosed entry represented by %d", revised.Withdrawn, made[1].ID)
			}
		})
	})
}
