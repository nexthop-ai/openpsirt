// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// StandingClaim is a live claim covering some of a finding's places, as the
// finding reports it.
type StandingClaim struct {
	Claim Claim
	// Decision is the representative row: the earliest of the claim's rows at
	// these places.
	Decision Decision
	// Places is how many of the finding's places the claim covers.
	Places int
	// Builds names every build the claim currently covers.
	Builds []string
	// ApprovedBy and ApprovedAt are the standing agreement, where one stands.
	ApprovedBy int64
	ApprovedAt *time.Time
	// Rows is how the claim's rows here stand: waiting, sent back to the
	// author, or approved. State is the claim's as a whole — approved only
	// where every live row is — because a representative row's state read
	// as the claim's, and one row approved beside forty-three sent back read
	// as "approved".
	Rows  RowsStanding
	State State
	// SentBackAt is the latest time any row was sent back, and
	// SentBackBecause the reason given then, so the finding can say what an
	// approver asked for.
	SentBackAt      *time.Time
	SentBackBecause string
}

// RowsStanding counts a claim's live rows by where they stand.
type RowsStanding struct {
	Proposed, SentBack, Approved int
}

// StandingAt reads the live claims covering any of a finding's places, at the
// versions the finding holds there.
//
// Grouped by claim, because that is what a person returning to a finding asks
// about: what stands here, in what state, agreed to by whom. Live means the
// row still holds its key — proposed or approved — so a claim waiting for a
// second person is reported as standing and pending rather than as absent.
//
// Matched by key rather than by place, which is the same match a finding
// makes when it asks whether a decision applies to it. A place is a pair of
// names, and the same pair sits in every build of the product at whatever
// version each ships: matched by place alone, a decision keyed at one build's
// version stood on a build shipping another.
func (s *Store) StandingAt(ctx context.Context, subject access.Subject, productID, issueID int64,
	at []finding.Deciding) ([]StandingClaim, error) {

	if len(at) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(at)*2)
	for _, place := range at {
		keys = append(keys, liveKeysFor(Place{
			ProductID: productID, VulnerabilityID: issueID, PlaceIdentity: place.PlaceIdentity,
			ComponentUpstream: place.ComponentUpstream, ConsumerUpstream: place.ConsumerUpstream,
		})...)
	}
	var rows []Decision
	// With the argument each row applies, which is the whole of what a reader
	// is shown: the outcome, the justification, the dates.
	if err := readableBy(s.db.NewSelect().Model(&rows).Relation("Claim"), subject, "de").
		Where("de.product_id = ?", productID).
		Where("de.vulnerability_id = ?", issueID).
		Where("de.live_key IN (?)", bun.List(keys)).
		Order("de.id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what stands here: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return s.groupByClaim(ctx, subject, rows)
}

// groupByClaim folds rows into one entry per claim, newest claim first.
func (s *Store) groupByClaim(ctx context.Context, subject access.Subject, rows []Decision) ([]StandingClaim, error) {
	order := []int64{}
	byClaim := map[int64]*StandingClaim{}
	var sentBack []int64
	for _, row := range rows {
		entry, seen := byClaim[row.ClaimID]
		if !seen {
			entry = &StandingClaim{Decision: row}
			byClaim[row.ClaimID] = entry
			order = append(order, row.ClaimID)
		}
		entry.Places++
		switch {
		case row.State == Approved:
			entry.Rows.Approved++
		case row.SentBackAt != nil:
			entry.Rows.SentBack++
			sentBack = append(sentBack, row.ClaimID)
			if entry.SentBackAt == nil || row.SentBackAt.After(*entry.SentBackAt) {
				when := *row.SentBackAt
				entry.SentBackAt = &when
			}
		default:
			entry.Rows.Proposed++
		}
	}
	for _, entry := range byClaim {
		entry.State = Proposed
		if entry.Rows.Approved == entry.Places {
			entry.State = Approved
		}
	}

	var claims []Claim
	if err := s.db.NewSelect().Model(&claims).
		Where("id IN (?)", bun.List(order)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the claims standing here: %w", err)
	}
	for _, claim := range claims {
		if entry, ok := byClaim[claim.ID]; ok {
			entry.Claim = claim
		}
	}
	if len(sentBack) > 0 {
		// The reason is the comment written when the rows were sent back:
		// the newest on the claim by somebody other than its author, since
		// the author's own remarks are answers rather than requests.
		var comments []Comment
		if err := s.db.NewSelect().Model(&comments).
			Where("claim_id IN (?)", bun.List(sentBack)).
			// Bounded. What is wanted is the newest comment on each claim
			// that is with its author, and this read every comment ever
			// written on every one of them to take one each — a claim people
			// have argued over is a conversation, and a page holds many.
			Order("id DESC").Limit(database.InBulk.Most).Scan(ctx); err != nil {
			return nil, fmt.Errorf("read why this was sent back: %w", err)
		}
		for _, comment := range comments {
			entry := byClaim[comment.ClaimID]
			if entry == nil || entry.SentBackBecause != "" || entry.SentBackAt == nil {
				continue
			}
			if comment.WrittenBy != entry.Claim.ProposedBy {
				entry.SentBackBecause = comment.Body
			}
		}
	}

	// The agreement that stands, where one does: the newest approval not
	// since withdrawn. One per claim, because one act is one argument.
	var approvals []Approval
	if err := s.db.NewSelect().Model(&approvals).
		Where("claim_id IN (?)", bun.List(claimsOf(rows))).
		Where("withdrawn_at IS NULL").
		Order("id DESC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who agreed: %w", err)
	}
	for _, approval := range approvals {
		entry := byClaim[approval.ClaimID]
		if entry == nil || entry.ApprovedAt != nil {
			continue
		}
		when := approval.ApprovedAt
		entry.ApprovedBy, entry.ApprovedAt = approval.ApprovedBy, &when
	}

	builds, err := s.buildsCovered(ctx, subject, order)
	if err != nil {
		return nil, err
	}

	out := make([]StandingClaim, 0, len(order))
	// Newest claim first: the most recent action is the one somebody
	// returning to the finding is most likely asking about.
	for i := len(order) - 1; i >= 0; i-- {
		entry := byClaim[order[i]]
		entry.Builds = builds[order[i]]
		out = append(out, *entry)
	}
	return out, nil
}

// Earlier is a decision once made at one of a finding's places that no longer
// applies, with the reasoning it rested on.
type Earlier struct {
	Decision  Decision
	Reasoning string
	// ApprovedBy is who last agreed to it, where anybody did. A withdrawn
	// agreement counts: the question is what was argued and by whom.
	ApprovedBy int64
}

// EarlierAt reads the decisions at a finding's places that stopped applying,
// newest first.
//
// The earlier argument is offered back rather than thrown away. A claim
// that lapsed on a version bump is usually still the right answer, and making
// somebody start from a blank page is how a tool teaches people to stop
// writing reasoning at all.
func (s *Store) EarlierAt(ctx context.Context, subject access.Subject, productID, issueID int64,
	places []string) ([]Earlier, error) {

	if len(places) == 0 {
		return nil, nil
	}
	var rows []Decision
	// With the argument each row applied, which is what is offered back.
	if err := readableBy(s.db.NewSelect().Model(&rows).Relation("Claim"), subject, "de").
		Where("de.product_id = ?", productID).
		Where("de.vulnerability_id = ?", issueID).
		Where("de.place_identity IN (?)", bun.List(places)).
		Where("de.state IN (?, ?)", Withdrawn, LapsedState).
		// Bounded, newest first. This is the whole history of what was
		// decided at these places and then stopped applying, which on a
		// long-lived product is every judgment ever made there — and a screen
		// reads the recent ones.
		Order("de.id DESC").Limit(database.InBulk.Most).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what was decided here before: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	reasoning, err := s.currentReasoning(ctx, rows)
	if err != nil {
		return nil, err
	}
	var approvals []Approval
	if err := s.db.NewSelect().Model(&approvals).
		Where("claim_id IN (?)", bun.List(claimsOf(rows))).
		Order("id DESC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who agreed: %w", err)
	}
	approver := map[int64]int64{}
	for _, approval := range approvals {
		if _, seen := approver[approval.ClaimID]; !seen {
			approver[approval.ClaimID] = approval.ApprovedBy
		}
	}
	out := make([]Earlier, 0, len(rows))
	for _, row := range rows {
		out = append(out, Earlier{
			Decision: row, Reasoning: reasoning[row.ID], ApprovedBy: approver[row.ClaimID],
		})
	}
	return out, nil
}

// Similar is an approved claim at the same places about another issue: an
// argument that may reach this one.
type Similar struct {
	Claim      Claim
	Decision   Decision
	Reasoning  string
	ApprovedBy int64
	ApprovedAt *time.Time
	// Issues is how many distinct issues the claim covers.
	Issues int
}

// similarOffered is how many similar claims a finding offers. A handful is a
// choice; a page is a search.
const similarOffered = 5

// SimilarAt reads the approved not-applicable claims standing at a finding's
// places about other issues, newest first.
func (s *Store) SimilarAt(ctx context.Context, subject access.Subject, productID, issueID int64,
	places []string) ([]Similar, error) {

	if len(places) == 0 {
		return nil, nil
	}
	var rows []Decision
	if err := readableBy(s.db.NewSelect().Model(&rows).Relation("Claim"), subject, "de").
		Where("de.product_id = ?", productID).
		Where("de.vulnerability_id <> ?", issueID).
		Where("de.place_identity IN (?)", bun.List(places)).
		Where("claim.outcome = ?", NotApplicable).
		Where("de.state = ?", Approved).
		Where("de.live_key IS NOT NULL").
		// Bounded in the statement rather than in the loop below. Five are
		// offered and every approved dismissal at these places crossed the
		// wire to pick them — a component at sixty places in a deployment
		// that has been triaging for a while is a page of rows read to keep
		// five. The ceiling is generous because the five are picked per
		// claim and a claim writes a row per place.
		Order("de.id DESC").Limit(database.InBulk.Most).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what was argued about other issues here: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	order := []int64{}
	representative := map[int64]Decision{}
	for _, row := range rows {
		if _, seen := representative[row.ClaimID]; seen {
			continue
		}
		representative[row.ClaimID] = row
		order = append(order, row.ClaimID)
		if len(order) == similarOffered {
			break
		}
	}

	var claims []Claim
	if err := s.db.NewSelect().Model(&claims).
		Where("id IN (?)", bun.List(order)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the claims standing here: %w", err)
	}
	byID := make(map[int64]Claim, len(claims))
	for _, claim := range claims {
		byID[claim.ID] = claim
	}

	// Every row of each claim, for the issue count and the standing
	// agreement — a claim about many issues has rows this finding does not
	// sit at. Narrowed like the rows above, so the count counts what the
	// reader may see rather than disclosing how many rows sit beyond it.
	var all []Decision
	if err := readableBy(s.db.NewSelect().Model(&all), subject, "de").
		Where("claim_id IN (?)", bun.List(order)).
		// Five claims, each of which may be a bulk act over two thousand
		// places. What is read off them is a count of issues and whether an
		// agreement stands, and both are answered by a bounded read.
		Limit(database.InBulk.Most).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what those claims cover: %w", err)
	}
	issues := map[int64]map[int64]bool{}
	for _, row := range all {
		if issues[row.ClaimID] == nil {
			issues[row.ClaimID] = map[int64]bool{}
		}
		issues[row.ClaimID][row.VulnerabilityID] = true
	}
	var approvals []Approval
	if err := s.db.NewSelect().Model(&approvals).
		Where("claim_id IN (?)", bun.List(order)).
		Where("withdrawn_at IS NULL").
		Order("id DESC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who agreed: %w", err)
	}
	agreed := map[int64]Approval{}
	for _, approval := range approvals {
		if _, seen := agreed[approval.ClaimID]; !seen {
			agreed[approval.ClaimID] = approval
		}
	}

	heads := make([]Decision, 0, len(order))
	for _, id := range order {
		heads = append(heads, representative[id])
	}
	reasoning, err := s.currentReasoning(ctx, heads)
	if err != nil {
		return nil, err
	}

	out := make([]Similar, 0, len(order))
	for _, id := range order {
		one := Similar{
			Claim: byID[id], Decision: representative[id],
			Reasoning: reasoning[representative[id].ID],
			Issues:    len(issues[id]),
		}
		if approval, ok := agreed[id]; ok {
			when := approval.ApprovedAt
			one.ApprovedBy, one.ApprovedAt = approval.ApprovedBy, &when
		}
		out = append(out, one)
	}
	return out, nil
}

// Elsewhere is an approved claim about this same issue at this same place, in
// another product.
//
// A place identity carries no product, deliberately, so that a place is
// recognized across variants. The same key recognizes it across products: two
// products shipping the same library under the same consumer are the same code
// in the same position, and a judgment one team made about it is evidence the
// other has no other way to reach.
type Elsewhere struct {
	Claim     Claim
	Decision  Decision
	Reasoning string
	// Product is which product it was decided in, by identifier. The name is
	// resolved by the caller, which is where names are resolved.
	ProductID  int64
	ApprovedBy int64
	ApprovedAt *time.Time
}

// DecidedElsewhere reads approved claims about this issue at these places in
// other products, newest first.
//
// Evidence, and never an outcome. It is offered the way a supplier's VEX
// statement is: as something to read and to quote, prefilling a reasoning where
// somebody asks for it and deciding nothing. Another team's judgment about
// their product is not a judgment about this one — what is shipped around the
// component differs, which is the whole reason a place is a component at a
// position rather than a component.
//
// Narrowed by what the subject may read, like every other query here, and
// for a sharper reason than most: the rows are in another product, so a join
// that did not carry the subject would hand somebody the reasoning, the
// approver and the existence of an embargoed judgment in a product they cannot
// see at all.
func (s *Store) DecidedElsewhere(ctx context.Context, subject access.Subject, productID,
	issueID int64, places []string) ([]Elsewhere, error) {

	if len(places) == 0 {
		return nil, nil
	}
	var rows []Decision
	if err := readableBy(s.db.NewSelect().Model(&rows).Relation("Claim"), subject, "de").
		Where("de.product_id <> ?", productID).
		Where("de.vulnerability_id = ?", issueID).
		Where("de.place_identity IN (?)", bun.List(places)).
		Where("de.state = ?", Approved).
		Where("de.live_key IS NOT NULL").
		Order("de.id DESC").Limit(database.InBulk.Most).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what was decided about this elsewhere: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	// One entry per claim, and at most a handful. A deployment carrying twenty
	// products would otherwise put twenty blocks of somebody else's reasoning
	// on a screen somebody is trying to decide on.
	order := []int64{}
	representative := map[int64]Decision{}
	for _, row := range rows {
		if _, seen := representative[row.ClaimID]; seen {
			continue
		}
		representative[row.ClaimID] = row
		order = append(order, row.ClaimID)
		if len(order) == similarOffered {
			break
		}
	}

	var claims []Claim
	if err := s.db.NewSelect().Model(&claims).
		Where("id IN (?)", bun.List(order)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the claims decided elsewhere: %w", err)
	}
	byID := make(map[int64]Claim, len(claims))
	for _, claim := range claims {
		byID[claim.ID] = claim
	}

	picked := make([]Decision, 0, len(order))
	for _, claimID := range order {
		picked = append(picked, representative[claimID])
	}
	reasoning, err := s.currentReasoning(ctx, picked)
	if err != nil {
		return nil, err
	}

	// Not one that has since been taken back, which both siblings in this file
	// already ask. Undoing a batch withdraws its agreement and deliberately
	// leaves the decision approved where another agreement still stands, so
	// without this the newest row is the withdrawn one and the block names
	// whoever took it back as the approver.
	var approvals []Approval
	if err := s.db.NewSelect().Model(&approvals).
		Where("claim_id IN (?)", bun.List(order)).
		Where("withdrawn_at IS NULL").
		Order("id DESC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who agreed elsewhere: %w", err)
	}
	approver := map[int64]Approval{}
	for _, approval := range approvals {
		if _, seen := approver[approval.ClaimID]; !seen {
			approver[approval.ClaimID] = approval
		}
	}

	out := make([]Elsewhere, 0, len(order))
	for _, claimID := range order {
		row := representative[claimID]
		one := Elsewhere{
			Claim: byID[claimID], Decision: row, Reasoning: reasoning[row.ID],
			ProductID: row.ProductID,
		}
		if agreed, ok := approver[claimID]; ok {
			one.ApprovedBy = agreed.ApprovedBy
			at := agreed.ApprovedAt
			one.ApprovedAt = &at
		}
		out = append(out, one)
	}
	return out, nil
}
