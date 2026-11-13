// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestAPromiseMovesOnlyToAVersionBoundedLikeTheVersionsItIsKeyedOn(t *testing.T) {
	// Changing a promise states a version as proposing one does, so it is
	// refused past the same bound, counted as sent, and leaves the decision as
	// it was.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		by := time.Now().UTC().AddDate(0, 0, 30).Truncate(time.Second)
		promised, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Occurrence: f.at(), Outcome: triage.UpgradeNeeded, UpgradeTo: "2.0", CommittedTo: &by,
			Reasoning: "Moving to the release that drops the parser.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}

		_, _, err = f.store.Repromise(ctx, f.triager, promised.DecisionID,
			strings.Repeat("9", 191)+"  ", by, "The release moved.")
		if !refusal.In(err) || !strings.Contains(err.Error(), "version the upgrade moves to") {
			t.Fatalf("a version past the bound answered %v, want a refusal naming it", err)
		}
		var stored triage.Decision
		if err := f.db.DB.NewSelect().Model(&stored).
			Where(`"cl"."id" = ?`, promised.DecisionID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if stored.UpgradeTo == nil || *stored.UpgradeTo != "2.0" {
			t.Errorf("the refused move left the decision moving to %v, want 2.0", stored.UpgradeTo)
		}

		if _, _, err := f.store.Repromise(ctx, f.triager, promised.DecisionID,
			strings.Repeat("é", 191), by, "The release moved."); err != nil {
			t.Errorf("a version at the bound was refused: %v", err)
		}
	})
}
