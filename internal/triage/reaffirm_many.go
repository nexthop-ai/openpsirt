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
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
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
	// Bounds bound every judgment the act re-makes, counted together. A
	// promise carries no bound (REQ-27).
	Bounds Bounds
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
		return nil, refusal.Errorf("a decision is recorded as made by whoever made it")
	}
	if len(r.ClaimIDs) == 0 {
		return nil, refusal.Errorf("nothing was selected, so there is nothing to re-affirm")
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
	var bounded []Proposal
	for _, claimID := range claims {
		plan, err := s.planReaffirm(ctx, subject, claimID, r.Reasoning, r.By)
		if err != nil {
			return nil, err
		}
		if err := permitted(subject, plan.proposals, s.now()); err != nil {
			return nil, err
		}
		if !plan.unbounded() {
			bounded = append(bounded, plan.proposals...)
		}
		plans = append(plans, plan)
	}
	// Bound what is written, over the whole act. Held per claim, a selection
	// of many claims each under the limit writes as many rows as it likes with
	// one sentence behind them, which is what the limit exists to stop. The
	// larger issue limit holds only where no claim in the act goes back to a
	// second person: one that does puts the whole act in front of a reader.
	limits, err := r.Bounds.within(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if err := limits.check(bounded); err != nil {
		return nil, err
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
		Join(finding.DecisionIssue).
		Join(`JOIN "vulnerability" AS "v" ON v.id = dv.issue_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`dv.issue_id AS "vulnerability_id"`).
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
	return refusal.Errorf("only the person who made a decision may re-affirm it, and somebody "+
		"else made the one at %s: take those out of the selection", strings.Join(named, ", "))
}

// ReaffirmingClaim is somebody saying every lapsed row of one action still
// holds.
type ReaffirmingClaim struct {
	// PreviousClaimID names the action whose rows stopped applying. The rows
	// are resolved here, for the reason a bulk judgment's places are: a caller
	// free to name them would be choosing which agreements get carried
	// forward.
	PreviousClaimID int64
	// Reasoning is the fresh reason, for all of them. One act is one argument,
	// which is what makes it one thing a second person can read.
	Reasoning string
	By        int64
	// Bounds bound a re-affirmed judgment, which this mostly is: the outcome
	// comes from the claim being re-made, so re-affirming a bulk dismissal
	// comes through here. A promise carries no bound, because the next scan
	// re-checks it; nothing re-checks a dismissal, which is the reason the
	// bound exists (REQ-27).
	Bounds Bounds
}

// Reaffirmed is what one bulk re-affirmation did.
type Reaffirmed struct {
	// PreviousClaimID is the claim that lapsed, and ClaimID the one that
	// re-makes it.
	PreviousClaimID int64
	ClaimID         int64
	// Decisions are the rows it wrote, and Places how many distinct places
	// they cover. A place at two versions in two builds is two rows, because
	// the versions are what a decision expires on.
	Decisions []int64
	Places    int
	// Waiting says a second person has to agree. One act, one approval: where
	// any row would need full approval, the whole of it does, because an
	// approver works at the unit the proposer acted at.
	Waiting bool
}

// ReaffirmClaim re-makes every lapsed row of one action, in one act.
//
// Bulk at the same three grains deciding has. A team answering one kernel
// issue writes a decision at each of its 45 places in one action; when the
// kernel moves, those 45 lapse, and restoring them one at a time is 45
// requests with 45 separately typed justifications. This is the one path that
// is safe to make cheap: a version bump is a prompt to re-check rather than a
// new claim, and the earlier agreement is already carried forward.
//
// It also breaks nothing REQ-28 asks for: approval, send-back and undo operate
// on the claim, and this brings re-affirmation to the same grain.
//
// Every escalation rule the single form applies is applied here, per row, and
// any one of them puts the whole act through full approval. An act whose rows
// were approved separately would be an approver agreeing to part of an argument
// they were shown whole.
func (s *Store) ReaffirmClaim(ctx context.Context, subject access.Subject,
	r ReaffirmingClaim) (Reaffirmed, error) {

	if r.By != subject.ID {
		return Reaffirmed{}, refusal.Errorf("a decision is recorded as made by whoever made it")
	}
	var out Reaffirmed
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		out = Reaffirmed{}
		made, err := within.reaffirmClaim(ctx, subject, r)
		if err != nil {
			return err
		}
		out = made
		return nil
	})
	return out, err
}

// reaffirmClaim is the whole of it, in the transaction that writes.
func (s *Store) reaffirmClaim(ctx context.Context, subject access.Subject,
	r ReaffirmingClaim) (Reaffirmed, error) {

	plan, err := s.planReaffirm(ctx, subject, r.PreviousClaimID, r.Reasoning, r.By)
	if err != nil {
		return Reaffirmed{}, err
	}
	// Bounded unless it is a promise. What decides is the outcome being
	// re-made rather than the act being a re-affirmation: this path carries
	// the previous claim's outcome, so a lapsed bulk dismissal re-made here is
	// a bulk judgment and nothing re-checks it. Unbounded it would write as
	// many rows as it liked, and with the earlier agreement carried on, nobody
	// would stand between the request and the rows.
	if err := permitted(subject, plan.proposals, s.now()); err != nil {
		return Reaffirmed{}, err
	}
	if !plan.unbounded() {
		limits, err := r.Bounds.within(ctx, s.db)
		if err != nil {
			return Reaffirmed{}, err
		}
		if err := limits.check(plan.proposals); err != nil {
			return Reaffirmed{}, err
		}
	}
	return s.writeReaffirm(ctx, plan)
}

// reaffirmPlan is one claim's re-affirmation worked out and not yet written.
type reaffirmPlan struct {
	previous  Claim
	lapsed    []Decision
	proposals []Proposal
	places    int
	full      bool
}

// unbounded reports whether the claim being re-made is a promise, which the
// cap on a bulk judgment does not reach (REQ-27).
func (p reaffirmPlan) unbounded() bool {
	return p.previous.Outcome == UpgradeNeeded
}

// planReaffirm works out what re-making one claim writes, reading everything
// it turns on inside the transaction that writes: which rows lapsed, where
// they sit now, how bad each issue is judged to be today, and whether there
// is an agreement to carry. Read outside, every one of them is an answer about
// a database that has since moved.
func (s *Store) planReaffirm(ctx context.Context, subject access.Subject,
	previousClaimID int64, reasoning string, by int64) (reaffirmPlan, error) {

	previous := new(Claim)
	if err := s.db.NewSelect().Model(previous).
		Where("id = ?", previousClaimID).Scan(ctx); err != nil {
		return reaffirmPlan{}, database.FromRead(err, ErrNotTheirs,
			fmt.Sprintf("read claim %d", previousClaimID))
	}
	var lapsed []Decision
	if err := stillLatest(s.db.NewSelect().Model(&lapsed).
		Where("de.claim_id = ?", previousClaimID).
		Where("de.state = ?", LapsedState)).
		Order("de.id ASC").Scan(ctx); err != nil {
		return reaffirmPlan{}, fmt.Errorf("read what lapsed under that claim: %w", err)
	}
	// Authorized against the rows before anything else is said about the
	// claim, and asked of every one, because a claim covering a disclosed
	// place and an undisclosed one is not one a public triager may re-make in
	// part.
	//
	// Before the proposer check (REQ-42). Refusing on the proposer first
	// answers a claim in a product the caller cannot see differently from one
	// that does not exist, which turns walking claim identifiers into a
	// directory of every product in the deployment.
	for _, row := range lapsed {
		if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			return reaffirmPlan{}, ErrNotTheirs
		}
	}
	if len(lapsed) == 0 {
		return reaffirmPlan{}, ErrNotTheirs
	}
	// The same rule the single form applies, asked once because a claim has
	// one proposer. Without it an approver could re-affirm, becoming proposer
	// of the new claim while their own earlier agreement is carried onto it.
	if previous.ProposedBy != subject.ID {
		return reaffirmPlan{}, refusal.Errorf(
			"only the person who made a decision may re-affirm it; anybody else proposes it afresh")
	}

	where, err := s.whereTheyAreNow(ctx, subject, lapsed)
	if err != nil {
		return reaffirmPlan{}, err
	}

	// The need for a second person, decided over the whole claim before any
	// of it is written. Any row escalating carries the rest with it: an
	// approver works at the unit the proposer acted at, and splitting the act
	// would be agreeing to part of an argument they were shown whole.
	carryable, err := s.approvalToCarry(ctx, previousClaimID, subject.ID)
	if err != nil {
		return reaffirmPlan{}, err
	}
	severity := map[[2]int64]int{}
	full := false
	for _, row := range lapsed {
		key := [2]int64{row.ProductID, row.VulnerabilityID}
		if _, asked := severity[key]; !asked {
			now, err := s.severityOf(ctx, row.ProductID, row.VulnerabilityID)
			if err != nil {
				return reaffirmPlan{}, err
			}
			severity[key] = now
		}
		if needsFullApproval(row, *previous, severity[key], carryable != nil) {
			full = true
		}
	}

	justification, mitigation, fixedVersion := "", "", ""
	if previous.Justification != nil {
		justification = *previous.Justification
	}
	if previous.Mitigation != nil {
		mitigation = *previous.Mitigation
	}
	if previous.FixedVersion != nil {
		fixedVersion = *previous.FixedVersion
	}

	proposals := make([]Proposal, 0, len(lapsed))
	places := map[string]bool{}
	// One proposal per place and versions, however many rows lead to it. A
	// place identity is names alone while a decision is keyed on the versions
	// too, so one component at two versions under one consumer is two lapsed
	// rows sharing a place — and writing the same live key twice refuses the
	// whole act with "a decision already stands here", which is false.
	done := map[string]bool{}
	for _, row := range lapsed {
		key := placeKey(row.ProductID, row.VulnerabilityID, row.PlaceIdentity)
		for _, at := range atVersions(row, where[key]) {
			written := key + "\x00" + at.ComponentUpstream + "\x00" + at.ConsumerUpstream
			if done[written] {
				continue
			}
			done[written] = true
			// The visibility it had. A re-affirmation says the same claim
			// still holds; it is not an occasion to change who may see it.
			at.Visibility = row.Visibility
			places[row.PlaceIdentity] = true
			proposals = append(proposals, Proposal{
				Place: at, Outcome: previous.Outcome,
				Justification: Justification(justification),
				Mitigation:    mitigation,
				DeferredUntil: previous.DeferredUntil,
				CommittedTo:   previous.CommittedTo,
				UpgradeTo:     orEmpty(previous.UpgradeTo),
				FixedVersion:  fixedVersion,
				Reasoning:     reasoning, By: by,
				SeverityCenti: severity[[2]int64{row.ProductID, row.VulnerabilityID}],
				NeedsApproval: full,
			})
		}
	}
	if len(proposals) == 0 {
		return reaffirmPlan{}, fmt.Errorf(
			"%w: none of what lapsed is open anywhere any more", ErrNothingOpen)
	}
	return reaffirmPlan{
		previous: *previous, lapsed: lapsed, proposals: proposals,
		places: len(places), full: full,
	}, nil
}

// writeReaffirm writes one planned re-affirmation: one act, one claim, one
// argument — the shape every other bulk write here takes.
func (s *Store) writeReaffirm(ctx context.Context, plan reaffirmPlan) (Reaffirmed, error) {
	first := plan.proposals[0]
	claim, err := s.newClaim(ctx, FindingClaim, first.By, &plan.previous.ID, "", first)
	if err != nil {
		return Reaffirmed{}, err
	}
	written, err := s.proposeAll(ctx, claim, plan.proposals)
	if err != nil {
		return Reaffirmed{}, err
	}
	out := Reaffirmed{
		PreviousClaimID: plan.previous.ID, ClaimID: claim.ID,
		Places: plan.places, Waiting: plan.full,
	}
	for _, one := range written {
		out.Decisions = append(out.Decisions, one.ID)
	}
	if plan.full {
		return out, nil
	}
	// Carried once, onto the claim, because an approval is an agreement to one
	// claim's words. Written per row it would be one agreement recorded forty
	// five times.
	if err := s.carryApprovalTo(ctx, written, *claim, plan.lapsed[0]); err != nil {
		return Reaffirmed{}, err
	}
	return out, nil
}

// stillLatest keeps the lapsed rows nothing has replaced, for a query over
// decision AS "de".
//
// A row is replaced where a decision of another claim was made at its place
// after it stopped standing. That is the re-affirmation that re-made it, or a
// fresh judgment, or one somebody made and then withdrew; in every case the
// later one is what the place last said. Re-making the earlier row would write
// a second live claim where the later one already stands, or bring back a
// judgment somebody since took back.
//
// A claim made before the row stopped standing replaces nothing. Two streams
// at two versions hold sibling claims at one place, keyed apart by the
// versions, and one lapsing leaves the other its own. Rows of one claim are
// one judgment and do not replace each other.
func stillLatest(q *bun.SelectQuery) *bun.SelectQuery {
	return q.Where(`NOT EXISTS (SELECT 1 FROM "decision" AS "newer"` +
		` WHERE newer.product_id = de.product_id` +
		// Filed under either issue, where one merged into the other.
		` AND EXISTS (SELECT 1 FROM "vulnerability" AS "sl"` +
		` JOIN "vulnerability" AS "so" ON "so"."issue_id" = "sl"."issue_id"` +
		` WHERE "sl"."id" = newer.vulnerability_id AND "so"."id" = de.vulnerability_id)` +
		` AND newer.place_identity = de.place_identity` +
		` AND newer.claim_id <> de.claim_id` +
		` AND newer.proposed_at >= de.ended_at)`)
}

// atVersions is where one lapsed row is re-made.
//
// At its own versions where the place is still open at them: a row lapsed
// because its issue was rated worse, whose code did not move. Re-made at every
// version the place is open at, it would take on builds it never covered, and a
// sibling claim at another version would collide with it. Where its versions
// are gone, the code moved, and it is re-made at every version the place is open
// at now.
func atVersions(row Decision, open []Place) []Place {
	component, consumer := orEmpty(row.ComponentUpstreamVersion), orEmpty(row.ConsumerUpstreamVersion)
	for _, at := range open {
		if at.ComponentUpstream == component && at.ConsumerUpstream == consumer {
			return []Place{at}
		}
	}
	return open
}

// placeKey identifies a lapsed row's place within its product.
func placeKey(productID, vulnerabilityID int64, placeIdentity string) string {
	return fmt.Sprintf("%d\x00%d\x00%s", productID, vulnerabilityID, placeIdentity)
}

// whereTheyAreNow is the versions each lapsed place sits at today, which is
// what the re-made decisions expire on.
//
// Narrowed by the two lists rather than by the pairs. No engine here spells
// a comparison against a pair of columns the same way, so the statement asks
// for the issues and the places separately — a superset — and the pairing is
// done on the way back.
//
// A place at two versions in two builds comes back twice, and is two decisions:
// the versions are what a decision expires on, so one row could not stand for
// both. A place that is open nowhere comes back not at all, which is a finding
// that closed rather than a fault.
func (s *Store) whereTheyAreNow(ctx context.Context, subject access.Subject,
	lapsed []Decision) (map[string][]Place, error) {

	issues := map[int64]bool{}
	identities := map[string]bool{}
	products := map[int64]bool{}
	for _, row := range lapsed {
		issues[row.VulnerabilityID] = true
		identities[row.PlaceIdentity] = true
		products[row.ProductID] = true
	}
	at := map[string][]Place{}
	for productID := range products {
		visible := access.Visible(subject, productID)
		if len(visible) == 0 {
			return nil, ErrNotTheirs
		}
		var rows []struct {
			VulnerabilityID   int64  `bun:"vulnerability_id"`
			PlaceIdentity     string `bun:"place_identity"`
			ComponentUpstream string `bun:"component_upstream"`
			ConsumerUpstream  string `bun:"consumer_upstream"`
			OnTag             int    `bun:"on_tag"`
		}
		err := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
			Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
			ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
			ColumnExpr(`f.place_identity AS "place_identity"`).
			ColumnExpr(finding.ComponentUpstreamExpr+` AS "component_upstream"`).
			ColumnExpr(finding.ConsumerUpstreamExpr+` AS "consumer_upstream"`).
			ColumnExpr(`MAX(CASE WHEN st.kind = ? THEN 1 ELSE 0 END) AS "on_tag"`, catalog.Tag).
			Where("st.product_id = ?", productID).
			Where("f.closed_at IS NULL").
			Where("f.visibility IN (?)", bun.List(visible)).
			Where("f.vulnerability_id IN (?)", bun.List(keysOf(issues))).
			Where("f.place_identity IN (?)", bun.List(wordsOf(identities))).
			GroupExpr("f.vulnerability_id, f.place_identity, c.upstream_version, c.version, "+
				"uc.upstream_version, uc.version").
			Scan(ctx, &rows)
		if err != nil {
			return nil, fmt.Errorf("read where these sit now: %w", err)
		}
		for _, row := range rows {
			key := placeKey(productID, row.VulnerabilityID, row.PlaceIdentity)
			at[key] = append(at[key], Place{
				ProductID: productID, VulnerabilityID: row.VulnerabilityID,
				PlaceIdentity:     row.PlaceIdentity,
				ComponentUpstream: row.ComponentUpstream,
				ConsumerUpstream:  row.ConsumerUpstream,
				OnTag:             row.OnTag == 1,
			})
		}
	}
	return at, nil
}

// keysOf and wordsOf are a set as a list, for binding into a statement.
func keysOf(set map[int64]bool) []int64 {
	out := make([]int64, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	return out
}

func wordsOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for word := range set {
		out = append(out, word)
	}
	return out
}
