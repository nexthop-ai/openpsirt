// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// ReaffirmingMany is somebody saying every one of several lapsed claims of
// theirs still holds.
type ReaffirmingMany struct {
	// ClaimIDs names the claims that lapsed. Their rows are resolved here, for
	// the reason a single claim's are: a caller free to name rows would be
	// choosing which agreements get carried forward.
	ClaimIDs []int64
	// Reasoning is the fresh reason, for all of them.
	Reasoning string
	By        int64
	// Cap bounds every judgment the act re-makes, counted together. A promise
	// carries no bound (REQ-27).
	Cap int
}

// ReaffirmMany re-makes several lapsed claims in one act.
//
// A version bump on a large component lapses many claims at once — a kernel
// stable release lapses every kernel decision — and each is a separate claim
// with its own outcome and justification. Each is re-made whole, the way
// re-affirming one claim is, under one shared reason.
//
// The need for a second person is decided per claim. Each claim is its own
// argument carrying its own earlier agreement, so one that needs a second look
// says nothing about the others. The act is still one transaction: refused
// whole or written whole.
func (s *Store) ReaffirmMany(ctx context.Context, subject access.Subject,
	r ReaffirmingMany) ([]Reaffirmed, error) {

	if r.By != subject.ID {
		return nil, fmt.Errorf("a decision is recorded as made by whoever made it")
	}
	if len(r.ClaimIDs) == 0 {
		return nil, fmt.Errorf("nothing was selected, so there is nothing to re-affirm")
	}
	var out []Reaffirmed
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		out = nil
		made, err := within.reaffirmMany(ctx, subject, r)
		if err != nil {
			return err
		}
		out = made
		return nil
	})
	return out, err
}

// reaffirmMany is the whole of it, in the transaction that writes.
func (s *Store) reaffirmMany(ctx context.Context, subject access.Subject,
	r ReaffirmingMany) ([]Reaffirmed, error) {

	seen := map[int64]bool{}
	claims := make([]int64, 0, len(r.ClaimIDs))
	for _, id := range r.ClaimIDs {
		if !seen[id] {
			seen[id] = true
			claims = append(claims, id)
		}
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i] < claims[j] })
	if err := s.refuseOthersClaims(ctx, subject, claims); err != nil {
		return nil, err
	}

	plans := make([]reaffirmPlan, 0, len(claims))
	bounded := 0
	for _, claimID := range claims {
		plan, err := s.planReaffirm(ctx, subject, claimID, r.Reasoning, r.By)
		if err != nil {
			return nil, err
		}
		if err := permitted(subject, plan.proposals, s.now()); err != nil {
			return nil, err
		}
		if !plan.unbounded() {
			bounded += len(plan.proposals)
		}
		plans = append(plans, plan)
	}
	// Bound what is written, over the whole act. Held per claim, a selection
	// of many claims each under the cap writes as many rows as it likes with
	// one sentence behind them, which is what the cap exists to stop.
	cap := r.Cap
	if cap <= 0 {
		cap = DefaultTogetherCap
	}
	if bounded > cap {
		return nil, fmt.Errorf("that is %d findings and the limit here is %d: narrow the "+
			"selection, or raise the limit deliberately", bounded, cap)
	}

	out := make([]Reaffirmed, 0, len(plans))
	for _, plan := range plans {
		made, err := s.writeReaffirm(ctx, plan)
		if err != nil {
			return nil, err
		}
		out = append(out, made)
	}
	return out, nil
}

// refuseOthersClaims refuses the act where any claim in it was made by
// somebody else, naming the issues so they can be taken out of the selection.
//
// Authorized first (REQ-42): a claim the subject may not act on is refused as
// though it were not there, before anything is said about who made it.
func (s *Store) refuseOthersClaims(ctx context.Context, subject access.Subject,
	claims []int64) error {

	var rows []struct {
		ClaimID         int64  `bun:"claim_id"`
		ProductID       int64  `bun:"product_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Visibility      string `bun:"visibility"`
		ProposedBy      int64  `bun:"proposed_by"`
		Identifier      string `bun:"identifier"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = de.vulnerability_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`de.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`de.visibility AS "visibility"`).
		ColumnExpr(`cl.proposed_by AS "proposed_by"`).
		ColumnExpr(`v.identifier AS "identifier"`).
		Where("de.claim_id IN (?)", bun.List(claims)).
		Where("de.state = ?", LapsedState).
		Apply(stillLatest).
		Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read who made these: %w", err)
	}
	for _, row := range rows {
		if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID,
			access.AsVisibility(row.Visibility)) {
			return ErrNotTheirs
		}
	}
	others := map[string]bool{}
	for _, row := range rows {
		if row.ProposedBy != subject.ID {
			others[row.Identifier] = true
		}
	}
	if len(others) == 0 {
		return nil
	}
	named := make([]string, 0, len(others))
	for name := range others {
		named = append(named, name)
	}
	sort.Strings(named)
	if len(named) > 10 {
		named = append(named[:10], fmt.Sprintf("and %d more", len(others)-10))
	}
	return fmt.Errorf("only the person who made a decision may re-affirm it, and somebody "+
		"else made the one at %s: take those out of the selection", strings.Join(named, ", "))
}
