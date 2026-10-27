// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ReaffirmingMany is somebody saying every one of several lapsed decisions of
// theirs still holds.
type ReaffirmingMany struct {
	// DecisionIDs names the decisions that lapsed. Their rows are resolved here, for
	// the reason a single decision's are: a caller free to name rows would be
	// choosing which agreements get carried forward.
	DecisionIDs []int64
	// Reasoning is the fresh reason, for all of them.
	Reasoning string
	By        int64
	// Bounds bound every decision the act re-makes, counted together. A
	// promise carries no bound (REQ-27).
	Bounds Bounds
}

// ReaffirmMany re-makes several lapsed decisions in one act.
//
// A version bump on a large component lapses many decisions at once — a kernel
// stable release lapses every kernel row — and each is a separate decision
// with its own outcome and justification. Each is re-made whole, the way
// re-affirming one decision is, under one shared reason.
//
// The need for a second person is decided per decision. Each decision is its own
// argument carrying its own earlier agreement, so one that needs a second look
// says nothing about the others. The act is still one transaction: refused
// whole or written whole.
func (s *Store) ReaffirmMany(ctx context.Context, subject access.Subject,
	r ReaffirmingMany) ([]Reaffirmed, error) {

	if r.By != subject.ID {
		return nil, refusal.Errorf("a decision is recorded as made by whoever made it")
	}
	if len(r.DecisionIDs) == 0 {
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
	decisions := make([]int64, 0, len(r.DecisionIDs))
	for _, id := range r.DecisionIDs {
		if !seen[id] {
			seen[id] = true
			decisions = append(decisions, id)
		}
	}
	sort.Slice(decisions, func(i, j int) bool { return decisions[i] < decisions[j] })
	if err := s.refuseOthersDecisions(ctx, subject, decisions); err != nil {
		return nil, err
	}

	plans := make([]reaffirmPlan, 0, len(decisions))
	var bounded []Proposal
	for _, decisionID := range decisions {
		plan, err := s.planReaffirm(ctx, subject, decisionID, r.Reasoning, r.By)
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
	// Bound what is written, over the whole act. Held per decision, a selection
	// of many decisions each under the limit writes as many rows as it likes with
	// one sentence behind them, which is what the limit exists to stop. The
	// larger issue limit holds only where no decision in the act goes back to a
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

// refuseOthersDecisions refuses the act where any decision in it was made by
// somebody else, naming the issues so they can be taken out of the selection.
//
// Authorized first (REQ-42): a decision the subject may not act on is refused as
// though it were not there, before anything is said about who made it.
func (s *Store) refuseOthersDecisions(ctx context.Context, subject access.Subject,
	decisions []int64) error {

	var rows []struct {
		DecisionID      int64  `bun:"decision_id"`
		ProductID       int64  `bun:"product_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Visibility      string `bun:"visibility"`
		ProposedBy      int64  `bun:"proposed_by"`
		Identifier      string `bun:"identifier"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		Join(finding.DecisionIssue).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "dv"."issue_id"`).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`"de"."product_id" AS "product_id"`).
		ColumnExpr(`"dv"."issue_id" AS "vulnerability_id"`).
		ColumnExpr(`"de"."visibility" AS "visibility"`).
		ColumnExpr(`"cl"."proposed_by" AS "proposed_by"`).
		ColumnExpr(`"v"."identifier" AS "identifier"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(decisions)).
		Where(`"de"."state" = ?`, LapsedState).
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

// ReaffirmingDecision is somebody saying every lapsed row of one action still
// holds.
type ReaffirmingDecision struct {
	// PreviousDecisionID names the action whose rows stopped applying. The rows
	// are resolved here, for the reason a bulk decision's occurrences are: a caller
	// free to name them would be choosing which agreements get carried
	// forward.
	PreviousDecisionID int64
	// Reasoning is the fresh reason, for all of them. One act is one argument,
	// which is what makes it one thing a second person can read.
	Reasoning string
	By        int64
	// Bounds bound a re-affirmed decision, which this mostly is: the outcome
	// comes from the decision being re-made, so re-affirming a bulk dismissal
	// comes through here. A promise carries no bound, because the next scan
	// re-checks it; nothing re-checks a dismissal, which is the reason the
	// bound exists (REQ-27).
	Bounds Bounds
}

// Reaffirmed is what one bulk re-affirmation did.
type Reaffirmed struct {
	// PreviousDecisionID is the decision that lapsed, and DecisionID the one that
	// re-makes it.
	PreviousDecisionID int64
	DecisionID         int64
	// DecisionOccurrences are the rows it wrote, and Occurrences how many distinct occurrences
	// they cover. An occurrence at two versions in two builds is two rows, because
	// the versions are what a row expires on.
	DecisionOccurrences []int64
	Occurrences         int
	// Waiting says a second person has to agree. One act, one approval: where
	// any row would need full approval, the whole of it does, because an
	// approver works at the unit the proposer acted at.
	Waiting bool
}

// ReaffirmDecision re-makes every lapsed row of one action, in one act.
//
// Bulk at the same three grains deciding has. A team answering one kernel
// issue writes a row at each of its 45 occurrences in one action; when the
// kernel moves, those 45 lapse, and restoring them one at a time is 45
// requests with 45 separately typed justifications. This is the one path that
// is safe to make cheap: a version bump is a prompt to re-check rather than a
// new decision, and the earlier agreement is already carried forward.
//
// It also breaks nothing REQ-28 asks for: approval, send-back and undo operate
// on the decision, and this brings re-affirmation to the same grain.
//
// Every escalation rule the single form applies is applied here, per row, and
// any one of them puts the whole act through full approval. An act whose rows
// were approved separately would be an approver agreeing to part of an argument
// they were shown whole.
func (s *Store) ReaffirmDecision(ctx context.Context, subject access.Subject,
	r ReaffirmingDecision) (Reaffirmed, error) {

	if r.By != subject.ID {
		return Reaffirmed{}, refusal.Errorf("a decision is recorded as made by whoever made it")
	}
	var out Reaffirmed
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		out = Reaffirmed{}
		made, err := within.reaffirmDecision(ctx, subject, r)
		if err != nil {
			return err
		}
		out = made
		return nil
	})
	return out, err
}

// reaffirmDecision is the whole of it, in the transaction that writes.
func (s *Store) reaffirmDecision(ctx context.Context, subject access.Subject,
	r ReaffirmingDecision) (Reaffirmed, error) {

	plan, err := s.planReaffirm(ctx, subject, r.PreviousDecisionID, r.Reasoning, r.By)
	if err != nil {
		return Reaffirmed{}, err
	}
	// Bounded unless it is a promise. What decides is the outcome being
	// re-made rather than the act being a re-affirmation: this path carries
	// the previous decision's outcome, so a lapsed bulk dismissal re-made here is
	// a bulk decision and nothing re-checks it. Unbounded it would write as
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

// reaffirmPlan is one decision's re-affirmation worked out and not yet written.
type reaffirmPlan struct {
	previous    Decision
	lapsed      []DecisionOccurrence
	proposals   []Proposal
	occurrences int
	full        bool
}

// unbounded reports whether the decision being re-made is a promise, which the
// cap on a bulk decision does not reach (REQ-27).
func (p reaffirmPlan) unbounded() bool {
	return p.previous.Outcome == UpgradeNeeded
}

// planReaffirm works out what re-making one decision writes, reading everything
// it turns on inside the transaction that writes: which rows lapsed, where
// they sit now, how bad each issue is judged to be today, and whether there
// is an agreement to carry. Read outside, every one of them is an answer about
// a database that has since moved.
func (s *Store) planReaffirm(ctx context.Context, subject access.Subject,
	previousDecisionID int64, reasoning string, by int64) (reaffirmPlan, error) {

	previous := new(Decision)
	if err := s.db.NewSelect().Model(previous).
		Where(`"id" = ?`, previousDecisionID).Scan(ctx); err != nil {
		return reaffirmPlan{}, database.FromRead(err, ErrNotTheirs,
			fmt.Sprintf("read decision %d", previousDecisionID))
	}
	var lapsed []DecisionOccurrence
	if err := stillLatest(s.db.NewSelect().Model(&lapsed).
		Where(`"de"."decision_id" = ?`, previousDecisionID).
		Where(`"de"."state" = ?`, LapsedState)).
		Order("de.id ASC").Scan(ctx); err != nil {
		return reaffirmPlan{}, fmt.Errorf("read what lapsed under that decision: %w", err)
	}
	// Authorized against the rows before anything else is said about the
	// decision, and asked of every one, because a decision covering a disclosed
	// occurrence and an undisclosed one is not one a public triager may re-make in
	// part.
	//
	// Before the proposer check (REQ-42). Refusing on the proposer first
	// answers a decision in a product the caller cannot see differently from one
	// that does not exist, which turns walking decision identifiers into a
	// directory of every product in the deployment.
	for _, row := range lapsed {
		if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			return reaffirmPlan{}, ErrNotTheirs
		}
	}
	if len(lapsed) == 0 {
		return reaffirmPlan{}, ErrNotTheirs
	}
	// The same rule the single form applies, asked once because a decision has
	// one proposer. Without it an approver could re-affirm, becoming proposer
	// of the new decision while their own earlier agreement is carried onto it.
	if previous.ProposedBy != subject.ID {
		return reaffirmPlan{}, refusal.Errorf(
			"only the person who made a decision may re-affirm it; anybody else proposes it afresh")
	}
	// And only a decision the list of what is yours to re-affirm holds, the rule
	// the single form asks. A decision with a withdrawn row is one somebody took
	// back, and re-making it carries an agreement onto what was withdrawn. A
	// decision at leads past their end of life alone is refused below, in the
	// words a decision there is refused in.
	reaffirmable, err := s.lapsedOfYours(subject).Where(`"de"."decision_id" = ?`, previousDecisionID).Exists(ctx)
	if err != nil {
		return reaffirmPlan{}, fmt.Errorf("read whether that decision is yours to re-affirm: %w", err)
	}
	if !reaffirmable {
		return reaffirmPlan{}, refusal.Errorf(
			"that decision has not lapsed, or something has been decided at that occurrence since")
	}

	where, err := s.whereTheyAreNow(ctx, subject, lapsed)
	if err != nil {
		return reaffirmPlan{}, err
	}

	// The need for a second person, decided over the whole decision before any
	// of it is written. Any row escalating carries the rest with it: an
	// approver works at the unit the proposer acted at, and splitting the act
	// would be agreeing to part of an argument they were shown whole.
	carryable, err := s.approvalToCarry(ctx, previousDecisionID, subject.ID)
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

	proposals := make([]Proposal, 0, len(lapsed))
	occurrences := map[string]bool{}
	// A lead past its end of life is kept as it stands, so the decision is
	// re-made at the rest of its occurrences and refused where none is left.
	ended := map[string]bool{}
	asked := map[string]bool{}
	pastEnd := false
	// One proposal per occurrence and versions, however many rows lead to it. An
	// occurrence identity is names alone while a row is keyed on the versions
	// too, so one component at two versions under one consumer is two lapsed
	// rows sharing an occurrence — and writing the same live key twice refuses the
	// whole act with "a decision already stands here", which is false.
	done := map[string]bool{}
	for _, row := range lapsed {
		key := occurrenceKey(row.ProductID, row.VulnerabilityID, row.OccurrenceIdentity)
		for _, at := range atVersions(row, where[key]) {
			written := key + "\x00" + at.ComponentUpstream + "\x00" + at.ConsumerUpstream
			if done[written] {
				continue
			}
			done[written] = true
			if at.Kind == kind.Analysis {
				lead := fmt.Sprintf("%d\x00%s", at.ProductID, at.OccurrenceIdentity)
				if !asked[lead] {
					asked[lead] = true
					switch err := finding.LeadEnded(ctx, s.db, at.ProductID, at.OccurrenceIdentity, s.now()); {
					case errors.Is(err, finding.ErrLeadPastEndOfLife):
						ended[lead] = true
					case err != nil:
						return reaffirmPlan{}, err
					}
				}
				if ended[lead] {
					pastEnd = true
					continue
				}
			}
			// The visibility it had. A re-affirmation says the same decision
			// still holds; it is not an occasion to change who may see it.
			at.Visibility = row.Visibility
			occurrences[row.OccurrenceIdentity] = true
			proposals = append(proposals, remade(*previous, at, reasoning, by,
				severity[[2]int64{row.ProductID, row.VulnerabilityID}], full))
		}
	}
	if len(proposals) == 0 && pastEnd {
		return reaffirmPlan{}, finding.ErrLeadPastEndOfLife
	}
	if len(proposals) == 0 {
		return reaffirmPlan{}, fmt.Errorf(
			"%w: none of what lapsed is open anywhere any more", ErrNothingOpen)
	}
	return reaffirmPlan{
		previous: *previous, lapsed: lapsed, proposals: proposals,
		occurrences: len(occurrences), full: full,
	}, nil
}

// writeReaffirm writes one planned re-affirmation: one act, one decision, one
// argument — the shape every other bulk write here takes.
func (s *Store) writeReaffirm(ctx context.Context, plan reaffirmPlan) (Reaffirmed, error) {
	first := plan.proposals[0]
	// The same decision re-made, so it keeps the builds it was made on.
	first.MadeAs = plan.previous.ID
	decision, err := s.newDecision(ctx, FindingDecision, first.By, &plan.previous.ID, "", first)
	if err != nil {
		return Reaffirmed{}, err
	}
	written, err := s.proposeAll(ctx, decision, plan.proposals)
	if err != nil {
		return Reaffirmed{}, err
	}
	out := Reaffirmed{
		PreviousDecisionID: plan.previous.ID, DecisionID: decision.ID,
		Occurrences: plan.occurrences, Waiting: plan.full,
	}
	for _, one := range written {
		out.DecisionOccurrences = append(out.DecisionOccurrences, one.ID)
	}
	if plan.full {
		return out, nil
	}
	// Carried once, onto the decision, because an approval is an agreement to one
	// decision's words. Written per row it would be one agreement recorded forty
	// five times.
	if err := s.carryApprovalTo(ctx, written, *decision, plan.lapsed[0]); err != nil {
		return Reaffirmed{}, err
	}
	return out, nil
}

// stillLatest keeps the lapsed rows nothing has replaced, for a query over
// decision_occurrence AS "de".
//
// A row is replaced where a row of another decision was made at its occurrence
// after it stopped standing. That is the re-affirmation that re-made it, or a
// fresh decision, or one somebody made and then withdrew; in every case the
// later one is what the occurrence last said. Re-making the earlier row would write
// a second live decision where the later one already stands, or bring back a
// decision somebody since took back.
//
// A decision made before the row stopped standing replaces nothing. Two streams
// at two versions hold sibling decisions at one occurrence, keyed apart by the
// versions, and one lapsing leaves the other its own. Rows of one decision are
// one decision and do not replace each other.
func stillLatest(q *bun.SelectQuery) *bun.SelectQuery {
	return q.Where(`NOT EXISTS (SELECT 1 FROM "decision_occurrence" AS "newer"` +
		` WHERE "newer"."product_id" = "de"."product_id"` +
		// Filed under either issue, where one merged into the other.
		` AND EXISTS (SELECT 1 FROM "vulnerability" AS "sl"` +
		` JOIN "vulnerability" AS "so" ON "so"."issue_id" = "sl"."issue_id"` +
		` WHERE "sl"."id" = "newer"."vulnerability_id" AND "so"."id" = "de"."vulnerability_id")` +
		` AND "newer"."occurrence_identity" = "de"."occurrence_identity"` +
		` AND "newer"."decision_id" <> "de"."decision_id"` +
		` AND "newer"."proposed_at" >= "de"."ended_at")`)
}

// atVersions is where one lapsed row is re-made.
//
// At its own versions where the occurrence is still open at them: a row lapsed
// because its issue was rated worse, whose code did not move. Re-made at every
// version the occurrence is open at, it would take on builds it never covered, and a
// sibling decision at another version would collide with it. Where its versions
// are gone, the code moved, and it is re-made at every version the occurrence is open
// at now.
func atVersions(row DecisionOccurrence, open []Occurrence) []Occurrence {
	component, consumer := orEmpty(row.ComponentUpstreamVersion), orEmpty(row.ConsumerUpstreamVersion)
	for _, at := range open {
		if at.ComponentUpstream == component && at.ConsumerUpstream == consumer {
			return []Occurrence{at}
		}
	}
	return open
}

// occurrenceKey identifies a lapsed row's occurrence within its product.
func occurrenceKey(productID, vulnerabilityID int64, occurrenceIdentity string) string {
	return fmt.Sprintf("%d\x00%d\x00%s", productID, vulnerabilityID, occurrenceIdentity)
}

// whereTheyAreNow is the versions each lapsed occurrence sits at today, which is
// what the re-made rows expire on.
//
// Narrowed by the two lists rather than by the pairs. No engine here spells
// a comparison against a pair of columns the same way, so the statement asks
// for the issues and the occurrences separately — a superset — and the pairing is
// done on the way back.
//
// An occurrence at two versions in two builds comes back twice, and is two rows:
// the versions are what a row expires on, so one row could not stand for
// both. An occurrence that is open nowhere comes back not at all, which is a finding
// that closed rather than a fault.
func (s *Store) whereTheyAreNow(ctx context.Context, subject access.Subject,
	lapsed []DecisionOccurrence) (map[string][]Occurrence, error) {

	issues := map[int64]bool{}
	identities := map[string]bool{}
	products := map[int64]bool{}
	for _, row := range lapsed {
		issues[row.VulnerabilityID] = true
		identities[row.OccurrenceIdentity] = true
		products[row.ProductID] = true
	}
	at := map[string][]Occurrence{}
	for productID := range products {
		visible := access.Visible(subject, productID)
		if len(visible) == 0 {
			return nil, ErrNotTheirs
		}
		var rows []struct {
			VulnerabilityID    int64  `bun:"vulnerability_id"`
			OccurrenceIdentity string `bun:"occurrence_identity"`
			ComponentUpstream  string `bun:"component_upstream"`
			ConsumerUpstream   string `bun:"consumer_upstream"`
			OnTag              int    `bun:"on_tag"`
			Kind               string `bun:"kind"`
		}
		err := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
			Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
			Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
			Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
			ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
			ColumnExpr(`"f"."occurrence_identity" AS "occurrence_identity"`).
			ColumnExpr(finding.ComponentUpstreamExpr+` AS "component_upstream"`).
			ColumnExpr(finding.ConsumerUpstreamExpr+` AS "consumer_upstream"`).
			ColumnExpr(`MAX(CASE WHEN "st"."kind" = ? THEN 1 ELSE 0 END) AS "on_tag"`, catalog.Tag).
			ColumnExpr(`MAX("f"."kind") AS "kind"`).
			Where(`"st"."product_id" = ?`, productID).
			Where(`"f"."closed_at" IS NULL`).
			Apply(ofKinds(kind.Decisions, "f")).
			Where(`"f"."visibility" IN (?)`, bun.List(visible)).
			Where(`"f"."vulnerability_id" IN (?)`, bun.List(keysOf(issues))).
			Where(`"f"."occurrence_identity" IN (?)`, bun.List(wordsOf(identities))).
			GroupExpr(`"f"."vulnerability_id", "f"."occurrence_identity", "c"."upstream_version", "c"."version", `+
				`"uc"."upstream_version", "uc"."version"`).
			Scan(ctx, &rows)
		if err != nil {
			return nil, fmt.Errorf("read where these sit now: %w", err)
		}
		for _, row := range rows {
			key := occurrenceKey(productID, row.VulnerabilityID, row.OccurrenceIdentity)
			at[key] = append(at[key], Occurrence{
				ProductID: productID, VulnerabilityID: row.VulnerabilityID,
				OccurrenceIdentity: row.OccurrenceIdentity,
				ComponentUpstream:  row.ComponentUpstream,
				ConsumerUpstream:   row.ConsumerUpstream,
				OnTag:              row.OnTag == 1,
				Kind:               kind.Kind(row.Kind),
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
