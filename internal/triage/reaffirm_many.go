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
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// LapsedAt is one row of the findings list somebody picked: an issue at a
// component, in one build.
type LapsedAt struct {
	TargetID        int64
	ComponentID     int64
	VulnerabilityID int64
}

// ReaffirmingMany is somebody saying every lapsed claim behind a selection
// still holds.
type ReaffirmingMany struct {
	// At names the rows picked. The claims are resolved here, for the reason a
	// single claim's rows are: a caller free to name them would be choosing
	// which agreements get carried forward.
	At []LapsedAt
	// Reasoning is the fresh reason, for all of them.
	Reasoning string
	By        int64
	// Cap bounds every judgment the act re-makes, counted together. A promise
	// carries no bound (REQ-27).
	Cap int
}

// ReaffirmMany re-makes every lapsed claim at the rows named, in one act.
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
	if len(r.At) == 0 {
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

	claims, err := s.lapsedClaimsAt(ctx, subject, r.At)
	if err != nil {
		return nil, err
	}
	if len(claims) == 0 {
		return nil, fmt.Errorf("%w: nothing selected has a lapsed decision to re-affirm",
			ErrNothingOpen)
	}
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

// lapsedClaimsAt is every claim with a lapsed row at the places the named rows
// cover, that nothing has replaced since.
//
// A row of the list is an issue at a source package in one build, so its
// places are the open findings of that issue across the fold. Narrowed to what
// the subject may read, like the list they picked from.
func (s *Store) lapsedClaimsAt(ctx context.Context, subject access.Subject,
	at []LapsedAt) ([]int64, error) {

	type group struct {
		target, component int64
	}
	issues := map[group][]int64{}
	var order []group
	for _, one := range at {
		key := group{one.TargetID, one.ComponentID}
		if _, seen := issues[key]; !seen {
			order = append(order, key)
		}
		issues[key] = append(issues[key], one.VulnerabilityID)
	}

	found := map[int64]bool{}
	for _, key := range order {
		fold, err := finding.InTheFold(ctx, s.db, key.component)
		if err != nil {
			return nil, err
		}
		var ids []int64
		places := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			ColumnExpr("1").
			Where("f.target_id = ?", key.target).
			Where("f.component_id IN (?)", bun.List(fold)).
			Where("f.closed_at IS NULL").
			Where("f.vulnerability_id = de.vulnerability_id").
			Where("f.place_identity = de.place_identity").
			Where("st.product_id = de.product_id")
		places = onlyDecidable(places, subject)
		err = stillLatest(s.db.NewSelect().
			TableExpr(`"decision" AS "de"`).
			ColumnExpr("DISTINCT de.claim_id").
			Where("de.state = ?", LapsedState).
			Where("de.vulnerability_id IN (?)", bun.List(issues[key])).
			Where("EXISTS (?)", places)).
			Scan(ctx, &ids)
		if err != nil {
			return nil, fmt.Errorf("read what lapsed at these findings: %w", err)
		}
		for _, id := range ids {
			found[id] = true
		}
	}
	claims := make([]int64, 0, len(found))
	for id := range found {
		claims = append(claims, id)
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i] < claims[j] })
	return claims, nil
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
