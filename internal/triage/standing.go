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
	"github.com/nexthop-ai/openpsirt/internal/filed"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// StandingDecision is a live decision covering some of a finding's occurrences, as the
// finding reports it.
type StandingDecision struct {
	Decision Decision
	// DecisionOccurrence is the representative row: the earliest of the decision's rows at
	// these occurrences.
	DecisionOccurrence DecisionOccurrence
	// Occurrences is how many of the finding's occurrences the decision covers.
	Occurrences int
	// Builds names every build the decision currently covers.
	Builds []string
	// ApprovedBy and ApprovedAt are the standing agreement, where one stands.
	ApprovedBy int64
	ApprovedAt *time.Time
	// Rows is how the decision's rows here stand: waiting, sent back to the
	// author, or approved. State is the decision's as a whole — approved only
	// where every live row is — because a representative row's state read
	// as the decision's, and one row approved beside forty-three sent back read
	// as "approved".
	Rows  RowsStanding
	State State
	// SentBackAt is the latest time any row was sent back, and
	// SentBackBecause the reason given then, so the finding can say what an
	// approver asked for.
	SentBackAt      *time.Time
	SentBackBecause string
}

// RowsStanding counts a decision's live rows by where they stand.
type RowsStanding struct {
	Proposed, SentBack, Approved int
}

// StandingAt reads the live decisions covering any of a finding's occurrences, at the
// versions the finding holds there.
//
// Grouped by decision, because that is what a person returning to a finding asks
// about: what stands here, in what state, agreed to by whom. Live means the
// row still holds its key — proposed or approved — so a decision waiting for a
// second person is reported as standing and pending rather than as absent.
//
// Matched by key rather than by occurrence, which is the same match a finding
// makes when it asks whether a decision applies to it. An occurrence is a pair of
// names, and the same pair sits in every build of the product at whatever
// version each ships: matched by occurrence alone, a decision keyed at one build's
// version stood on a build shipping another.
func (s *Store) StandingAt(ctx context.Context, subject access.Subject, productID, issueID int64,
	at []finding.Deciding) ([]StandingDecision, error) {

	if len(at) == 0 {
		return nil, nil
	}
	// A live row holds its key under the issue it is read as, including
	// one filed under an issue that merged into this one.
	keys := make([]string, 0, len(at)*2)
	for _, occurrence := range at {
		keys = append(keys, liveKeysFor(Occurrence{
			ProductID: productID, VulnerabilityID: issueID, OccurrenceIdentity: occurrence.OccurrenceIdentity,
			ComponentUpstream: occurrence.ComponentUpstream, ConsumerUpstream: occurrence.ConsumerUpstream,
		})...)
	}
	var rows []DecisionOccurrence
	// With the argument each row applies, which is the whole of what a reader
	// is shown: the outcome, the justification, the dates.
	if err := readableBy(s.db.NewSelect().Model(&rows).Relation("Decision"), subject, "de").
		Where(`"de"."product_id" = ?`, productID).
		Where(finding.FiledUnder(filed.DecisionIssue), issueID).
		Where(`"de"."live_key" IN (?)`, bun.List(keys)).
		Order("de.id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what stands here: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return s.groupByDecision(ctx, subject, rows)
}

// groupByDecision folds rows into one entry per decision, newest decision first.
func (s *Store) groupByDecision(ctx context.Context, subject access.Subject, rows []DecisionOccurrence) ([]StandingDecision, error) {
	order := []int64{}
	byDecision := map[int64]*StandingDecision{}
	var sentBack []int64
	for _, row := range rows {
		entry, seen := byDecision[row.DecisionID]
		if !seen {
			entry = &StandingDecision{DecisionOccurrence: row}
			byDecision[row.DecisionID] = entry
			order = append(order, row.DecisionID)
		}
		entry.Occurrences++
		switch {
		case row.State == Approved:
			entry.Rows.Approved++
		case row.SentBackAt != nil:
			entry.Rows.SentBack++
			sentBack = append(sentBack, row.DecisionID)
			if entry.SentBackAt == nil || row.SentBackAt.After(*entry.SentBackAt) {
				when := *row.SentBackAt
				entry.SentBackAt = &when
			}
		default:
			entry.Rows.Proposed++
		}
	}
	for _, entry := range byDecision {
		entry.State = Proposed
		if entry.Rows.Approved == entry.Occurrences {
			entry.State = Approved
		}
	}

	var decisions []Decision
	if err := s.db.NewSelect().Model(&decisions).
		Where(`"id" IN (?)`, bun.List(order)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the decisions standing here: %w", err)
	}
	for _, decision := range decisions {
		if entry, ok := byDecision[decision.ID]; ok {
			entry.Decision = decision
		}
	}
	if len(sentBack) > 0 {
		// The reason is the comment written when the rows were sent back:
		// the newest on the decision by somebody other than its author, since
		// the author's own remarks are answers rather than requests.
		var comments []Comment
		if err := s.db.NewSelect().Model(&comments).
			Where(`"decision_id" IN (?)`, bun.List(sentBack)).
			// Bounded. What is wanted is the newest comment on each decision
			// that is with its author, and this read every comment ever
			// written on every one of them to take one each — a decision people
			// have argued over is a conversation, and a page holds many.
			Order("id DESC").Limit(int64(database.InBulk.Most)).Scan(ctx); err != nil {
			return nil, fmt.Errorf("read why this was sent back: %w", err)
		}
		for _, comment := range comments {
			entry := byDecision[comment.DecisionID]
			if entry == nil || entry.SentBackBecause != "" || entry.SentBackAt == nil {
				continue
			}
			if comment.WrittenBy != entry.Decision.ProposedBy {
				entry.SentBackBecause = comment.Body
			}
		}
	}

	agreed, err := s.standingApprovals(ctx, decisionsOf(rows))
	if err != nil {
		return nil, err
	}
	for decisionID, approval := range agreed {
		if entry := byDecision[decisionID]; entry != nil {
			when := approval.ApprovedAt
			entry.ApprovedBy, entry.ApprovedAt = approval.ApprovedBy, &when
		}
	}

	builds, err := s.buildsCovered(ctx, subject, order)
	if err != nil {
		return nil, err
	}

	out := make([]StandingDecision, 0, len(order))
	// Newest decision first: the most recent action is the one somebody
	// returning to the finding is most likely asking about.
	for i := len(order) - 1; i >= 0; i-- {
		entry := byDecision[order[i]]
		entry.Builds = builds[order[i]]
		out = append(out, *entry)
	}
	return out, nil
}

// Earlier is a decision occurrence once made at one of a finding's occurrences that no longer
// applies, with the reasoning it rested on.
type Earlier struct {
	DecisionOccurrence DecisionOccurrence
	Reasoning          string
	// ApprovedBy is who last agreed to it, where anybody did. A withdrawn
	// agreement counts: the question is what was argued and by whom.
	ApprovedBy int64
}

// EarlierAt reads the decision occurrences at a finding's occurrences that stopped applying,
// newest first.
//
// The earlier argument is offered back rather than thrown away. A decision
// that lapsed on a version bump is usually still the right answer, and making
// somebody start from a blank page is how a tool teaches people to stop
// writing reasoning at all.
func (s *Store) EarlierAt(ctx context.Context, subject access.Subject, productID, issueID int64,
	occurrences []string) ([]Earlier, error) {

	if len(occurrences) == 0 {
		return nil, nil
	}
	var rows []DecisionOccurrence
	// With the argument each row applied, which is what is offered back.
	if err := readableBy(s.db.NewSelect().Model(&rows).Relation("Decision"), subject, "de").
		Where(`"de"."product_id" = ?`, productID).
		Where(finding.FiledUnder(filed.DecisionIssue), issueID).
		Where(`"de"."occurrence_identity" IN (?)`, bun.List(occurrences)).
		Where(`"de"."state" IN (?, ?)`, Withdrawn, LapsedState).
		// Bounded, newest first. This is the whole history of what was
		// decided at these occurrences and then stopped applying, which on a
		// long-lived product is every decision ever made there — and a screen
		// reads the recent ones.
		Order("de.id DESC").Limit(int64(database.InBulk.Most)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what was decided here before: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	reasoning, err := s.currentReasoning(ctx, rows)
	if err != nil {
		return nil, err
	}
	if err := s.withholdPartReasoning(ctx, subject, rows, reasoning); err != nil {
		return nil, err
	}
	var approvals []Approval
	if err := s.db.NewSelect().Model(&approvals).
		Where(`"decision_id" IN (?)`, bun.List(decisionsOf(rows))).
		Order("id DESC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who agreed: %w", err)
	}
	approver := map[int64]int64{}
	for _, approval := range approvals {
		if _, seen := approver[approval.DecisionID]; !seen {
			approver[approval.DecisionID] = approval.ApprovedBy
		}
	}
	out := make([]Earlier, 0, len(rows))
	for _, row := range rows {
		out = append(out, Earlier{
			DecisionOccurrence: row, Reasoning: reasoning[row.ID], ApprovedBy: approver[row.DecisionID],
		})
	}
	return out, nil
}

// Similar is an approved decision at the same occurrences about another issue: an
// argument that may reach this one.
type Similar struct {
	Decision           Decision
	DecisionOccurrence DecisionOccurrence
	Reasoning          string
	ApprovedBy         int64
	ApprovedAt         *time.Time
	// Issues is how many distinct issues the decision covers.
	Issues int
}

// similarOffered is how many similar decisions a finding offers. A handful is a
// choice; a page is a search.
const similarOffered = 5

// SimilarAt reads the approved not-applicable decisions standing at a finding's
// occurrences about other issues, newest first.
func (s *Store) SimilarAt(ctx context.Context, subject access.Subject, productID, issueID int64,
	occurrences []string) ([]Similar, error) {

	if len(occurrences) == 0 {
		return nil, nil
	}
	var rows []DecisionOccurrence
	if err := readableBy(s.db.NewSelect().Model(&rows).Relation("Decision"), subject, "de").
		Where(`"de"."product_id" = ?`, productID).
		Where("NOT ("+finding.FiledUnder(filed.DecisionIssue)+")", issueID).
		Where(`"de"."occurrence_identity" IN (?)`, bun.List(occurrences)).
		Where(`"decision"."outcome" = ?`, NotApplicable).
		Where(`"de"."state" = ?`, Approved).
		Where(`"de"."live_key" IS NOT NULL`).
		// Bounded in the statement rather than in the loop below. Five are
		// offered and every approved dismissal at these occurrences crossed the
		// wire to pick them — a component at sixty occurrences in a deployment
		// that has been triaging for a while is a page of rows read to keep
		// five. The ceiling is generous because the five are picked per
		// decision and a decision writes a row per occurrence.
		Order("de.id DESC").Limit(int64(database.InBulk.Most)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what was argued about other issues here: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	found, err := s.evidenceOf(ctx, subject, rows, "read the decisions standing here")
	if err != nil {
		return nil, err
	}
	order := found.order

	// How many issues each decision covers, counted over every row of it: a
	// decision about many issues has rows this finding does not sit at. Narrowed
	// like the rows above, so the count counts what the reader may see
	// rather than disclosing how many rows sit beyond it. Counted in the
	// statement, which answers one row per decision however many occurrences each
	// wrote.
	var counted []struct {
		DecisionID int64 `bun:"decision_id"`
		Issues     int   `bun:"issues"`
	}
	if err := readableBy(s.db.NewSelect().Model((*DecisionOccurrence)(nil)), subject, "de").
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		// Counted as the issues the rows are read as, so two names a report
		// merged are one issue.
		Join(finding.DecisionIssue).
		ColumnExpr(`COUNT(DISTINCT "dv"."issue_id") AS "issues"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(order)).
		GroupExpr(`"de"."decision_id"`).
		Scan(ctx, &counted); err != nil {
		return nil, fmt.Errorf("read what those decisions cover: %w", err)
	}
	issues := make(map[int64]int, len(counted))
	for _, row := range counted {
		issues[row.DecisionID] = row.Issues
	}

	out := make([]Similar, 0, len(order))
	for _, id := range order {
		row := found.head[id]
		one := Similar{
			Decision: found.decision[id], DecisionOccurrence: row,
			Reasoning: found.reasoning[row.ID],
			Issues:    issues[id],
		}
		one.ApprovedBy, one.ApprovedAt = found.agreedOn(id)
		out = append(out, one)
	}
	return out, nil
}

// Elsewhere is an approved decision about this same issue at this same occurrence, in
// another product.
//
// An occurrence identity carries no product, deliberately, so that an occurrence is
// recognized across variants. The same key recognizes it across products: two
// products shipping the same library under the same consumer are the same code
// in the same position, and a decision one team made about it is evidence the
// other has no other way to reach.
type Elsewhere struct {
	Decision           Decision
	DecisionOccurrence DecisionOccurrence
	Reasoning          string
	// Product is which product it was decided in, by identifier. The name is
	// resolved by the caller, which is where names are resolved.
	ProductID  int64
	ApprovedBy int64
	ApprovedAt *time.Time
}

// DecidedElsewhere reads approved decisions about this issue at these occurrences in
// other products, newest first.
//
// Evidence, and never an outcome. It is offered the way a supplier's VEX
// statement is: as something to read and to quote, prefilling a reasoning where
// somebody asks for it and deciding nothing. Another team's decision about
// their product is not a decision about this one — what is shipped around the
// component differs, which is the whole reason an occurrence is a component at a
// position rather than a component.
//
// Narrowed by what the subject may read, like every other query here, and
// for a sharper reason than most: the rows are in another product, so a join
// that did not carry the subject would hand somebody the reasoning, the
// approver and the existence of an embargoed decision in a product they cannot
// see at all.
func (s *Store) DecidedElsewhere(ctx context.Context, subject access.Subject, productID,
	issueID int64, occurrences []string) ([]Elsewhere, error) {

	if len(occurrences) == 0 {
		return nil, nil
	}
	var rows []DecisionOccurrence
	if err := readableBy(s.db.NewSelect().Model(&rows).Relation("Decision"), subject, "de").
		Where(`"de"."product_id" <> ?`, productID).
		Where(finding.FiledUnder(filed.DecisionIssue), issueID).
		Where(`"de"."occurrence_identity" IN (?)`, bun.List(occurrences)).
		Where(`"de"."state" = ?`, Approved).
		Where(`"de"."live_key" IS NOT NULL`).
		Order("de.id DESC").Limit(int64(database.InBulk.Most)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what was decided about this elsewhere: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	// One entry per decision, and at most a handful. A deployment carrying twenty
	// products would otherwise put twenty blocks of somebody else's reasoning
	// on a screen somebody is trying to decide on.
	found, err := s.evidenceOf(ctx, subject, rows, "read the decisions decided elsewhere")
	if err != nil {
		return nil, err
	}

	out := make([]Elsewhere, 0, len(found.order))
	for _, decisionID := range found.order {
		row := found.head[decisionID]
		one := Elsewhere{
			Decision: found.decision[decisionID], DecisionOccurrence: row, Reasoning: found.reasoning[row.ID],
			ProductID: row.ProductID,
		}
		one.ApprovedBy, one.ApprovedAt = found.agreedOn(decisionID)
		out = append(out, one)
	}
	return out, nil
}

// evidence is what a set of rows offers as evidence: the first row of
// each decision, at most a handful of decisions, in the order the rows came.
type evidence struct {
	order []int64
	// head is the row kept for each decision, by decision.
	head     map[int64]DecisionOccurrence
	decision map[int64]Decision
	// reasoning is each kept row's current reasoning as the reader may see
	// it, by row.
	reasoning map[int64]string
	// agreed is the agreement standing on each decision, where one does.
	agreed map[int64]Approval
}

// evidenceOf reads the decisions a set of rows offers, with their current
// reasoning withheld where the reader may not see all of it, and the
// agreement standing on each. readingDecisions names the read of the decisions in
// an error.
func (s *Store) evidenceOf(ctx context.Context, subject access.Subject, rows []DecisionOccurrence,
	readingDecisions string) (evidence, error) {

	order, head := firstPerDecision(rows, similarOffered)
	var decisions []Decision
	if err := s.db.NewSelect().Model(&decisions).
		Where(`"id" IN (?)`, bun.List(order)).Scan(ctx); err != nil {
		return evidence{}, fmt.Errorf("%s: %w", readingDecisions, err)
	}
	byID := make(map[int64]Decision, len(decisions))
	for _, decision := range decisions {
		byID[decision.ID] = decision
	}
	heads := make([]DecisionOccurrence, 0, len(order))
	for _, id := range order {
		heads = append(heads, head[id])
	}
	reasoning, err := s.currentReasoning(ctx, heads)
	if err != nil {
		return evidence{}, err
	}
	if err := s.withholdPartReasoning(ctx, subject, heads, reasoning); err != nil {
		return evidence{}, err
	}
	agreed, err := s.standingApprovals(ctx, order)
	if err != nil {
		return evidence{}, err
	}
	return evidence{order: order, head: head, decision: byID, reasoning: reasoning, agreed: agreed}, nil
}

// agreedOn is who agreed to a decision and when, or nobody.
func (e evidence) agreedOn(decisionID int64) (int64, *time.Time) {
	approval, ok := e.agreed[decisionID]
	if !ok {
		return 0, nil
	}
	when := approval.ApprovedAt
	return approval.ApprovedBy, &when
}

// firstPerDecision keeps the first row of each decision, in the order the rows came,
// and stops at most decisions. It answers the decisions in that order and the row
// kept for each.
func firstPerDecision(rows []DecisionOccurrence, most int) ([]int64, map[int64]DecisionOccurrence) {
	order := []int64{}
	representative := map[int64]DecisionOccurrence{}
	for _, row := range rows {
		if _, seen := representative[row.DecisionID]; seen {
			continue
		}
		representative[row.DecisionID] = row
		order = append(order, row.DecisionID)
		if len(order) == most {
			break
		}
	}
	return order, representative
}

// standingApprovals reads the agreement that stands on each decision, where one
// does: the newest approval not since withdrawn. One per decision, because one
// act is one argument.
//
// A withdrawn approval is never the answer. Undoing a batch withdraws its
// agreement and leaves the row approved where another agreement still
// stands, so the newest row can be the withdrawn one, and reading it would name
// whoever took it back as the approver.
func (s *Store) standingApprovals(ctx context.Context, decisionIDs []int64) (map[int64]Approval, error) {
	agreed := map[int64]Approval{}
	if len(decisionIDs) == 0 {
		return agreed, nil
	}
	var approvals []Approval
	if err := s.db.NewSelect().Model(&approvals).
		Where(`"decision_id" IN (?)`, bun.List(decisionIDs)).
		Where(`"withdrawn_at" IS NULL`).
		Order("id DESC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who agreed: %w", err)
	}
	for _, approval := range approvals {
		if _, seen := agreed[approval.DecisionID]; !seen {
			agreed[approval.DecisionID] = approval
		}
	}
	return agreed, nil
}
