// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/filed"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// The threshold a second person's agreement turns on.
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

// DeferredAt is the same total for several places of one issue in one
// product, keyed by place, in one statement for all of them. A form deciding
// about those places says whether a deferral would stand on its own, and that
// is the total it is measured against.
//
// Counted over the deferrals the subject may read. A deferral sits at the
// place it defers, so somebody deciding about a place reads every deferral
// made there, and the total is the one the gate measures.
func (s *Store) DeferredAt(ctx context.Context, subject access.Subject, productID,
	vulnerabilityID int64, places []string) (map[string]time.Duration, error) {
	decisions := make([]Decision, 0, len(places))
	for i, place := range places {
		decisions = append(decisions, Decision{
			ID: int64(-1 - i), ProductID: productID, VulnerabilityID: vulnerabilityID,
			PlaceIdentity: place,
		})
	}
	totals, err := s.deferredSoFarAs(ctx, decisions, func(q *bun.SelectQuery) *bun.SelectQuery {
		return readableBy(q, subject, "de")
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]time.Duration, len(places))
	for _, decision := range decisions {
		out[decision.PlaceIdentity] = totals[decision.ID]
	}
	return out, nil
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
	return s.deferredSoFarAs(ctx, decisions, func(q *bun.SelectQuery) *bun.SelectQuery { return q })
}

// deferredSoFarAs is deferredSoFar over the deferrals a narrowing admits.
func (s *Store) deferredSoFarAs(ctx context.Context, decisions []Decision,
	narrow func(*bun.SelectQuery) *bun.SelectQuery) (map[int64]time.Duration, error) {
	return s.deferredWith(ctx, decisions, narrow, nil)
}

// deferredWith is deferredSoFarAs with a stretch being asked for added to
// each decision's place, keyed by the decision. A stretch overlapping one
// already held is counted once with it, as two recorded ones are.
func (s *Store) deferredWith(ctx context.Context, decisions []Decision,
	narrow func(*bun.SelectQuery) *bun.SelectQuery, asking map[int64]span) (map[int64]time.Duration, error) {
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

	// Every deferral of the issue, including those filed under an issue that
	// merged into it: a place put off under either name was put off.
	issueOf, err := finding.IssuesOf(ctx, s.db, issueIDs)
	if err != nil {
		return nil, err
	}
	asked := make([]int64, 0, len(issueOf))
	for _, issue := range issueOf {
		asked = append(asked, issue)
	}
	var deferrals []Decision
	if err := narrow(s.db.NewSelect().Model(&deferrals).Relation("Claim")).
		Where("de.product_id IN (?)", bun.List(productIDs)).
		Where(finding.FiledUnderAny(filed.DecisionIssue), bun.List(asked)).
		Where("claim.outcome = ?", Deferred).
		// Withdrawn and lapsed ones included, for the span they were in force.
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
	filed := make([]int64, 0, len(deferrals))
	for _, deferral := range deferrals {
		filed = append(filed, deferral.VulnerabilityID)
	}
	deferredAs, err := finding.IssuesOf(ctx, s.db, filed)
	if err != nil {
		return nil, err
	}
	held := spans[place]{}
	for _, deferral := range deferrals {
		deferral.VulnerabilityID = deferredAs[deferral.VulnerabilityID]
		// Measured from when it was asked for, so a deferral that has not yet
		// run out counts the whole of what it asked for rather than only the
		// part already spent. The question is how long this has been put off
		// for, not how long it has been put off so far.
		if one, ok := heldDeferral(deferral); ok {
			key := place{deferral.ProductID, deferral.VulnerabilityID, deferral.PlaceIdentity}
			held[key] = append(held[key], one)
		}
	}
	for _, decision := range decisions {
		key := place{decision.ProductID, issueOf[decision.VulnerabilityID], decision.PlaceIdentity}
		if more, ok := asking[decision.ID]; ok {
			totals[decision.ID] = spans[place]{key: append(slices.Clone(held[key]), more)}.total(key)
			continue
		}
		totals[decision.ID] = held.total(key)
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

// heldSpan is when one deferral row put its place off.
//
// From when it was asked for to the date it returns on, cut short where the
// row ended before that date: taken back, or lapsed when the versions it was
// keyed on moved. An ending shortens the time something was hidden and does
// not erase it: counted as zero, the cumulative threshold was defeated by
// withdrawing and deferring again, one sub-threshold span at a time, forever.
// Counted whole, a row that stopped applying would still be putting its place
// off.
//
// Not held where it ended before it took effect.
func heldSpan(proposedAt, until time.Time, state State, endedAt *time.Time) (span, bool) {
	if state.Ended() && endedAt != nil && endedAt.Before(until) {
		until = *endedAt
	}
	if !until.After(proposedAt) {
		return span{}, false
	}
	return span{from: proposedAt, to: until}, true
}

// heldDeferral is heldSpan for a decision read with its claim.
func heldDeferral(deferral Decision) (span, bool) {
	if deferral.Claim == nil || deferral.Claim.DeferredUntil == nil {
		return span{}, false
	}
	return heldSpan(deferral.ProposedAt, *deferral.Claim.DeferredUntil, deferral.State,
		deferral.EndedAt)
}

// span is one stretch a place was put off for.
type span struct{ from, to time.Time }

// spans are the stretches deferrals held each place for.
type spans[K comparable] map[K][]span

// total is how long the place was put off for, with overlapping stretches
// counted once. One claim keyed at two versions writes two rows over one
// stretch, and a deferral re-affirmed after it lapsed carries its date into
// the new claim: either way the place was put off once.
func (all spans[K]) total(key K) time.Duration {
	held := slices.Clone(all[key])
	slices.SortFunc(held, func(a, b span) int { return a.from.Compare(b.from) })
	var sum time.Duration
	var open span
	for i, one := range held {
		switch {
		case i == 0:
			open = one
		case one.from.After(open.to):
			sum += open.to.Sub(open.from)
			open = one
		case one.to.After(open.to):
			open.to = one.to
		}
	}
	if len(held) > 0 {
		sum += open.to.Sub(open.from)
	}
	return sum
}

// deferralThreshold is how much cumulative postponement a place may carry
// before a further deferral needs a second person.
//
// Read here rather than handed in, and read inside whatever transaction the
// caller opened. It is an input to the control: read outside, a retry — or a
// first attempt that merely waited — decided against a policy that has since
// changed, and recorded a claim as needing nobody under one that says it does.
func (s *Store) deferralThreshold(ctx context.Context) (time.Duration, error) {
	return DeferralThreshold(ctx, s.db)
}

// DeferralThreshold reads the threshold as the gate and every screen measure
// it: in whole days, because a deferral is dated in days and a form is told
// the threshold in days.
func DeferralThreshold(ctx context.Context, db bun.IDB) (time.Duration, error) {
	return setting.NewStore(db).Days(ctx, setting.DeferralThreshold, DefaultDeferralThreshold)
}

// DefaultDeferralThreshold is the shipped span, where nobody has said.
//
// A starting point rather than a recommendation, like every other shipped
// number here.
const DefaultDeferralThreshold = 30 * 24 * time.Hour

// bind resolves what a promise made here is gated against: the earliest
// deadline among everything the act covers.
//
// Read here rather than handed in, because it is a stored value that a
// re-rating or an arriving scan moves — so a value read before the
// transaction opened gates the promise against a deadline that may be gone by
// the time it is written, and a retry re-reads everything else and would keep
// this one stale. REQ-71: nothing a transaction depends on is read outside it.
//
// One binding over the whole set rather than one per place: an act covering a
// critical and a medium is gated by the critical, however many mediums are in
// it.
func (s *Store) bind(ctx context.Context, subject access.Subject, proposals []Proposal) error {
	var targets []int64
	places := make([]finding.At, 0, len(proposals))
	var productID int64
	for _, p := range proposals {
		if len(p.BindingAcross) == 0 {
			continue
		}
		if len(targets) == 0 {
			targets, productID = p.BindingAcross, p.Place.ProductID
		}
		places = append(places, finding.At{
			VulnerabilityID: p.Place.VulnerabilityID,
			PlaceIdentity:   p.Place.PlaceIdentity,
		})
	}
	if len(places) == 0 {
		return nil
	}
	// The store here is only a receiver: what the read runs on is this
	// transaction, which DeadlineAt takes as its own argument for exactly this
	// reason.
	binding, err := (&finding.Store{}).DeadlineAt(ctx, s.db, subject, productID, targets, places)
	if err != nil {
		return err
	}
	for i := range proposals {
		if len(proposals[i].BindingAcross) > 0 {
			proposals[i].Binding = binding
		}
	}
	return nil
}

// gate works out whether each of these proposals needs a second person, and
// records the answer on them.
//
// A claim's wait is not something its author states. As a field on the
// proposal, worked out by the caller before the transaction opens and taken on
// trust, it has the same shape the binding deadline does and the same
// consequence: a policy changing between the answer and the
// write, or a deferral landing on the same place in between, stored a claim
// as needing nobody under a rule that says it does. Nothing reported it.
func (s *Store) gate(ctx context.Context, subject access.Subject, proposals []Proposal) error {
	threshold, err := s.deferralThreshold(ctx)
	if err != nil {
		return err
	}
	if err := s.bind(ctx, subject, proposals); err != nil {
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

	// The stretch asked for, from this store's own clock, like every other
	// time decision here. A date already past asks for no time at all, so a
	// back-dated deferral adds nothing and subtracts nothing.
	asking := map[int64]span{}
	if p.DeferredUntil != nil {
		now := s.now()
		if p.DeferredUntil.After(now) {
			asking[-1] = span{from: now, to: *p.DeferredUntil}
		}
	}

	// Merged with the postponements already asked for about this same place,
	// so a stretch this deferral shares with one still in force is counted
	// once.
	total, err := s.deferredWith(ctx, []Decision{{
		ID: -1, ProductID: p.Place.ProductID, VulnerabilityID: p.Place.VulnerabilityID,
		PlaceIdentity: p.Place.PlaceIdentity,
	}}, func(q *bun.SelectQuery) *bun.SelectQuery { return q }, asking)
	if err != nil {
		return false, err
	}
	return total[-1] >= threshold, nil
}
