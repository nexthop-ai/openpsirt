// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// MadeOn is one build a claim was made on: the build on screen when it was
// proposed, or one the person chose to cover beside it.
//
// A decision is keyed without a build and reaches every build whose versions
// match (REQ-25), so this is the only record of which builds somebody was
// looking at. A build the decision reaches by lookup is never recorded here:
// telling that build apart from the ones it was made on is what the record is
// for.
type MadeOn struct {
	bun.BaseModel `bun:"table:claim_build,alias:cb"`

	ID       int64 `bun:"id,pk,autoincrement"`
	ClaimID  int64 `bun:"claim_id,notnull"`
	TargetID int64 `bun:"target_id,notnull"`
}

// recordMadeOn writes the builds a new claim was made on, inside the
// transaction that writes the claim.
//
// The builds the proposal names, and those of the claim it is made as where it
// names one: a claim re-made after its code moved, or the rows an approver set
// aside, is the same judgment, made on the same builds.
func (s *Store) recordMadeOn(ctx context.Context, claimID int64, p Proposal) error {
	targets := append([]int64(nil), p.MadeOn...)
	if p.MadeAs != 0 {
		held, err := madeOnOf(ctx, s.db, []int64{p.MadeAs})
		if err != nil {
			return err
		}
		targets = append(targets, held[p.MadeAs]...)
	}
	seen := map[int64]bool{}
	rows := make([]MadeOn, 0, len(targets))
	for _, target := range targets {
		if target == 0 || seen[target] {
			continue
		}
		seen[target] = true
		rows = append(rows, MadeOn{ClaimID: claimID, TargetID: target})
	}
	if len(rows) == 0 {
		return nil
	}
	if err := database.InBatches(ctx, s.db, rows); err != nil {
		return fmt.Errorf("record the builds a claim was made on: %w", err)
	}
	return nil
}

// madeOnOf is the builds each of these claims was made on, in the order they
// were identified. A claim with nothing recorded is absent.
func madeOnOf(ctx context.Context, db bun.IDB, claims []int64) (map[int64][]int64, error) {
	out := map[int64][]int64{}
	if len(claims) == 0 {
		return out, nil
	}
	var rows []MadeOn
	where, args := database.InAnyOf("cb.claim_id", claims)
	if err := db.NewSelect().Model(&rows).Where(where, args...).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the builds a claim was made on: %w", err)
	}
	for _, row := range rows {
		out[row.ClaimID] = append(out[row.ClaimID], row.TargetID)
	}
	for id := range out {
		sort.Slice(out[id], func(i, j int) bool { return out[id][i] < out[id][j] })
	}
	return out, nil
}
