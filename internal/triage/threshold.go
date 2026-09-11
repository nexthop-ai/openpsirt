package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// When a second person has to agree.
//
// The deployment's separation-of-duties gate (REQ-24): what counts as a
// deferral standing on its own, how long a place has been put off across every
// claim that put it off, and the one function every write path asks before it
// records anything. It sat in the file that renders the review queue, which is
// the screen the gate produces work for rather than the rule itself.

// DeferredSoFar is the total time a finding has been put off, across every
// deferral ever recorded about the same place.
//
// Cumulative rather than per deferral, because otherwise deferring repeatedly
// for just under the threshold never needs agreement — and four consecutive
// twenty-nine day deferrals are a year nobody approved.
func (s *Store) DeferredSoFar(ctx context.Context, decision Decision) (time.Duration, error) {
	decision.ID = -1
	totals, err := s.deferredSoFar(ctx, []Decision{decision})
	if err != nil {
		return 0, err
	}
	return totals[decision.ID], nil
}

// deferredSoFar reads, in one statement for all of them, how long each of
// these decisions' places has been put off for in total, keyed by the
// decision asked about.
//
// One statement for the page rather than one per row: the deferrals in the
// products on the page are read together and matched to each decision's
// place here. The set is small — a deferral is a decision of ours, in these
// products, and most decisions are not deferrals — where a lookup per row
// was a statement per queue entry.
func (s *Store) deferredSoFar(ctx context.Context, decisions []Decision) (map[int64]time.Duration, error) {
	totals := make(map[int64]time.Duration, len(decisions))
	if len(decisions) == 0 {
		return totals, nil
	}
	products := map[int64]bool{}
	issues := map[int64]bool{}
	for _, decision := range decisions {
		products[decision.ProductID] = true
		issues[decision.VulnerabilityID] = true
	}
	productIDs := make([]int64, 0, len(products))
	for id := range products {
		productIDs = append(productIDs, id)
	}
	issueIDs := make([]int64, 0, len(issues))
	for id := range issues {
		issueIDs = append(issueIDs, id)
	}

	var deferrals []Decision
	if err := s.db.NewSelect().Model(&deferrals).Relation("Claim").
		Where("de.product_id IN (?)", bun.List(productIDs)).
		Where("de.vulnerability_id IN (?)", bun.List(issueIDs)).
		Where("claim.outcome = ?", Deferred).
		// Withdrawn ones included, for the span they were actually in force.
		// Excluded outright, the threshold was defeated by taking a deferral
		// back and making another: each one alone stayed under the line, the
		// running total reset to zero every time, and a place stayed hidden
		// indefinitely with no second person ever seeing it. A withdrawal
		// shortens the time something was put off; it does not erase it.
		Where("claim.deferred_until IS NOT NULL").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read how long these have been put off: %w", err)
	}

	type place struct {
		product, issue int64
		at             string
	}
	spans := map[place]time.Duration{}
	for _, deferral := range deferrals {
		if deferral.Claim == nil || deferral.Claim.DeferredUntil == nil {
			continue
		}
		// Measured from when it was asked for, so a deferral that has not yet
		// run out counts the whole of what it asked for rather than only the
		// part already spent. The question is how long this has been put off
		// for, not how long it has been put off so far.
		if span := heldFor(deferral); span > 0 {
			spans[place{deferral.ProductID, deferral.VulnerabilityID, deferral.PlaceIdentity}] += span
		}
	}
	for _, decision := range decisions {
		totals[decision.ID] = spans[place{decision.ProductID, decision.VulnerabilityID, decision.PlaceIdentity}]
	}
	return totals, nil
}

// commitmentGated reports whether a promise to act by a date needs a second
// person, given the deadline the work it covers already has.
//
// One spelling, because there are three acts that make a promise — recording
// one on a finding, declaring an upgrade on a component, and moving either —
// and a gate written out at each of them is a gate that comes to say three
// things.
//
// Inside the deadline, nothing is hidden for longer than the policy already
// allowed, which is ordinary triage: gating every planned upgrade would put
// the most routine act of all through the review queue. Past it, the promise
// defers the worst thing the act covers, which is exactly what a second
// person is for.
//
// Both absences gate. A commitment with no date is not a commitment. And
// where nothing it covers has a deadline there is no date the promise can be
// inside — the exemption is "this hides nothing the policy did not already
// allow", and a place with no deadline allowed nothing. Reading that the
// other way made a product below its own triage line the one place a promise
// could hide a finding for years on one signature.
func commitmentGated(committedTo, binding *time.Time) bool {
	if committedTo == nil || binding == nil {
		return true
	}
	return committedTo.After(*binding)
}

// heldFor is how long a deferral put its place off for.
//
// From when it was asked for to the date it returns on, cut short where it was
// taken back before that date. A withdrawal shortens the time something was
// hidden and does not erase it: counted as zero, the cumulative threshold was
// defeated by withdrawing and deferring again, one sub-threshold span at a
// time, forever. Counted whole, taking a decision back would read as avoiding
// the work.
//
// Zero or less where it was taken back before it took effect, which is the
// case the old exclusion was right about.
func heldFor(deferral Decision) time.Duration {
	if deferral.Claim == nil || deferral.Claim.DeferredUntil == nil {
		return 0
	}
	until := *deferral.Claim.DeferredUntil
	if deferral.State == Withdrawn && deferral.EndedAt != nil && deferral.EndedAt.Before(until) {
		until = *deferral.EndedAt
	}
	return until.Sub(deferral.ProposedAt)
}

// deferralThreshold is how much cumulative postponement a place may carry
// before a further deferral needs a second person.
//
// Read here rather than handed in, and read inside whatever transaction the
// caller opened. It is an input to the control: read outside, a retry — or a
// first attempt that merely waited — decided against a policy that has since
// changed, and recorded a claim as needing nobody under one that says it does.
func (s *Store) deferralThreshold(ctx context.Context) (time.Duration, error) {
	return setting.NewStore(s.db).Duration(ctx, setting.DeferralThreshold,
		DefaultDeferralThreshold)
}

// DefaultDeferralThreshold is the shipped span, where nobody has said.
//
// A starting point rather than a recommendation, like every other shipped
// number here.
const DefaultDeferralThreshold = 30 * 24 * time.Hour

// gate works out whether each of these proposals needs a second person, and
// records the answer on them.
//
// **Whether a claim is waiting is not something its author states.** It was a
// field on the proposal, worked out by the caller before the transaction
// opened and taken on trust — the same shape the binding deadline had, and
// with the same consequence: a policy changing between the answer and the
// write, or a deferral landing on the same place in between, stored a claim
// as needing nobody under a rule that says it does. Nothing reported it.
func (s *Store) gate(ctx context.Context, proposals []Proposal) error {
	threshold, err := s.deferralThreshold(ctx)
	if err != nil {
		return err
	}
	for i := range proposals {
		needs, err := s.NeedsApproval(ctx, proposals[i], threshold)
		if err != nil {
			return err
		}
		proposals[i].NeedsApproval = needs
	}
	return nil
}

// NeedsApproval reports whether a proposal may stand on its own.
//
// Hiding risk needs a second person. The exception is a short deferral: a
// quick "not this sprint" is ordinary triage and gating it would put every
// routine act through a queue, which is how a queue stops being read.
//
// "Short" is measured against everything this finding has already been put off
// for. Otherwise the exception swallows the rule one twenty-nine day deferral
// at a time.
func (s *Store) NeedsApproval(ctx context.Context, p Proposal, threshold time.Duration) (bool, error) {
	if !p.Outcome.HidesRisk() {
		return false, nil
	}
	// A promise to act by a date is gated against the deadline the work
	// already has rather than against a configured span.
	if p.Outcome.Commits() {
		return commitmentGated(p.CommittedTo, p.Binding), nil
	}
	if p.Outcome != Deferred {
		return true, nil
	}
	if threshold <= 0 {
		return true, nil
	}

	asking := time.Duration(0)
	if p.DeferredUntil != nil {
		// Measured from this store's own clock, like every other time decision
		// here, and never negative. A date already past asks for no time at
		// all; letting it come out negative would let a back-dated deferral
		// subtract from what a finding has already been postponed for and slip
		// under the threshold.
		if span := p.DeferredUntil.Sub(s.now()); span > 0 {
			asking = span
		}
	}

	// What has already been asked for about this same place.
	already, err := s.DeferredSoFar(ctx, Decision{
		ProductID: p.Place.ProductID, VulnerabilityID: p.Place.VulnerabilityID,
		PlaceIdentity: p.Place.PlaceIdentity,
	})
	if err != nil {
		return false, err
	}
	return already+asking >= threshold, nil
}
