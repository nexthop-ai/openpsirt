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
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// SeveralStates is the word for a decision whose matching rows are not all in one
// state.
const SeveralStates = "mixed"

// AuditedDecision is one decision as the record lists it: the argument once, with how
// much of it the question asked matched.
//
// Every count is of the rows the filters matched and the reader may see. A
// decision is listed because some of its rows answer the question, and counting
// the rest into it would show rows nobody asked for, or rows the reader may not
// read.
type AuditedDecision struct {
	Decision Decision
	// Reasoning is the words the decision currently rests on.
	Reasoning string
	// ProposedByName and Approvals are the separation-of-duties record, as on
	// a single decision.
	ProposedByName string
	Approvals      []Agreed
	// Issue, Component, Version, Consumer, Product and ProductName name what
	// the earliest matching row was about. The counts below say how
	// representative that is.
	Issue, Component, Version, Consumer string
	Product, ProductName                string
	// ProposedAt is when the earliest matching row was proposed, which is the
	// moment a period filter asked about. A decision made by setting rows aside is
	// stamped when that happened, later than the rows it took.
	ProposedAt time.Time
	// Rows is the matching rows; Issues, Occurrences and Products are the
	// distinct issues, occurrences and products among them. An issue is counted as
	// the issue its rows are read as, so rows filed under two names that were
	// merged are one issue. Components is the
	// distinct component names at those occurrences, counted through the findings
	// the reader may read.
	Rows, Issues, Occurrences, Products, Components int
	// States is the matching rows by state.
	States map[State]int
	// Standing is how many of the matching rows apply now.
	Standing int
}

// State is the decision's matching rows in one word: their state where they share
// one, and SeveralStates where they do not.
func (c AuditedDecision) State() string {
	word := ""
	for _, state := range States() {
		if c.States[state] == 0 {
			continue
		}
		if word != "" {
			return SeveralStates
		}
		word = string(state)
	}
	return word
}

// BySomebodyElse reports whether somebody other than the proposer has a
// standing agreement on the decision.
func (c AuditedDecision) BySomebodyElse() bool { return bySomebodyElse(c.Approvals, c.ProposedByName) }

// AuditDecisions returns the record a decision at a time, newest first: every decision
// with a row the filters match and the reader may see, ordered by the newest
// such row.
//
// Grouped when read. A decision covering forty occurrences is one argument by one
// person, and a list of it forty times over is a list nobody reads. The rows
// stay in the per-occurrence read, which the file is written from.
func (s *Store) AuditDecisions(ctx context.Context, subject access.Subject, f Filter,
	from, to time.Time, limit, offset int) ([]AuditedDecision, int, error) {

	limit = database.AList.Of(limit)
	narrow := auditedBy(subject, f, from, to)
	matching := func() *bun.SelectQuery {
		return narrow(s.db.NewSelect().Model((*DecisionOccurrence)(nil)))
	}

	grouped := func() *bun.SelectQuery {
		return matching().
			ColumnExpr(`"de"."decision_id" AS "decision_id"`).
			ColumnExpr(`MAX("de"."id") AS "newest"`).
			GroupExpr(`"de"."decision_id"`)
	}
	total, err := s.db.NewSelect().TableExpr(`(?) AS "page"`, grouped()).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count the decisions in the record: %w", err)
	}
	var page []struct {
		DecisionID int64 `bun:"decision_id"`
		Newest     int64 `bun:"newest"`
	}
	if err := grouped().OrderExpr(`"newest" DESC`).
		Limit(int64(limit)).Offset(int64(offset)).Scan(ctx, &page); err != nil {
		return nil, 0, fmt.Errorf("read the decisions in the record: %w", err)
	}
	if len(page) == 0 {
		return nil, int(total), nil
	}
	ids := make([]int64, 0, len(page))
	for _, row := range page {
		ids = append(ids, row.DecisionID)
	}

	var sizes []struct {
		DecisionID  int64 `bun:"decision_id"`
		Rows        int   `bun:"decisions"`
		Issues      int   `bun:"issues"`
		Occurrences int   `bun:"places"`
		Products    int   `bun:"products"`
		Earliest    int64 `bun:"earliest"`
		// Proposed is a pointer because an aggregate reads as nullable.
		Proposed *time.Time `bun:"proposed"`
	}
	if err := matching().
		Join(finding.DecisionIssue).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`COUNT(*) AS "decisions"`).
		ColumnExpr(`COUNT(DISTINCT "dv"."issue_id") AS "issues"`).
		ColumnExpr(`COUNT(DISTINCT "de"."occurrence_identity") AS "places"`).
		ColumnExpr(`COUNT(DISTINCT "de"."product_id") AS "products"`).
		ColumnExpr(`MIN("de"."id") AS "earliest"`).
		ColumnExpr(`MIN("de"."proposed_at") AS "proposed"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(ids)).
		GroupExpr(`"de"."decision_id"`).Scan(ctx, &sizes); err != nil {
		return nil, 0, fmt.Errorf("count what each decision covers: %w", err)
	}

	var byState []struct {
		DecisionID  int64 `bun:"decision_id"`
		State       State `bun:"state"`
		Occurrences int   `bun:"decisions"`
	}
	if err := matching().
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`"de"."state" AS "state"`).
		ColumnExpr(`COUNT(*) AS "decisions"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(ids)).
		GroupExpr(`"de"."decision_id"`).GroupExpr(`"de"."state"`).Scan(ctx, &byState); err != nil {
		return nil, 0, fmt.Errorf("count each decision's states: %w", err)
	}

	// What applies now, the condition AuditedOccurrence.Standing reads off one row.
	standing, held := finding.InForce()
	var inForce []struct {
		DecisionID  int64 `bun:"decision_id"`
		Occurrences int   `bun:"decisions"`
	}
	if err := matching().
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`COUNT(*) AS "decisions"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(ids)).
		Where(`"de"."live_key" IS NOT NULL`).Where(standing, held...).
		GroupExpr(`"de"."decision_id"`).Scan(ctx, &inForce); err != nil {
		return nil, 0, fmt.Errorf("count what each decision still covers: %w", err)
	}

	// Component names through the findings at the matching occurrences, narrowed to
	// the findings the reader may read: a name read off a finding they may not
	// is the disclosure, even as a count.
	components := matching().
		Join(finding.DecisionIssue).
		Join(`JOIN "finding" AS "f" ON `+finding.DecisionAtOccurrence("f")).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id" AND "st"."product_id" = "de"."product_id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`COUNT(DISTINCT "c"."name_folded") AS "components"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(ids)).
		Apply(ofKinds(kind.Decisions, "f")).
		GroupExpr(`"de"."decision_id"`)
	components = readableFindings(components, subject, "f", `"st"."product_id"`)
	var named []struct {
		DecisionID int64 `bun:"decision_id"`
		Components int   `bun:"components"`
	}
	if err := components.Scan(ctx, &named); err != nil {
		return nil, 0, fmt.Errorf("count the components each decision covers: %w", err)
	}

	var decisions []Decision
	if err := s.db.NewSelect().Model(&decisions).
		Where(`"cl"."id" IN (?)`, bun.List(ids)).Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("read the decisions in the record: %w", err)
	}
	proposers := make([]int64, 0, len(decisions))
	for _, decision := range decisions {
		proposers = append(proposers, decision.ProposedBy)
	}
	agreed, people, err := s.agreedAndNamed(ctx, ids, proposers)
	if err != nil {
		return nil, 0, err
	}
	reasoning, err := s.reasoningPerDecision(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	hidden, err := s.partlyHidden(ctx, subject, ids)
	if err != nil {
		return nil, 0, err
	}
	for id := range hidden {
		delete(reasoning, id)
	}
	representatives := make([]DecisionOccurrence, 0, len(sizes))
	for _, size := range sizes {
		representatives = append(representatives, DecisionOccurrence{ID: size.Earliest})
	}
	about, err := s.aboutEach(ctx, representatives)
	if err != nil {
		return nil, 0, err
	}

	gathered := make(map[int64]*AuditedDecision, len(ids))
	for _, decision := range decisions {
		gathered[decision.ID] = &AuditedDecision{
			Decision: decision, Reasoning: reasoning[decision.ID],
			ProposedByName: people[decision.ProposedBy],
			Approvals:      agreed[decision.ID],
			States:         map[State]int{},
		}
	}
	for _, size := range sizes {
		entry, held := gathered[size.DecisionID]
		if !held {
			continue
		}
		entry.Rows, entry.Issues, entry.Occurrences = size.Rows, size.Issues, size.Occurrences
		entry.Products = size.Products
		if size.Proposed != nil {
			entry.ProposedAt = *size.Proposed
		}
		if what, known := about[size.Earliest]; known {
			entry.Issue, entry.Component, entry.Version = what.Issue, what.Component, what.Version
			entry.Consumer, entry.Product, entry.ProductName = what.Consumer, what.Product, what.ProductName
		}
	}
	for _, row := range byState {
		if entry, held := gathered[row.DecisionID]; held {
			entry.States[row.State] += row.Occurrences
		}
	}
	for _, row := range inForce {
		if entry, held := gathered[row.DecisionID]; held {
			entry.Standing = row.Occurrences
		}
	}
	for _, row := range named {
		if entry, held := gathered[row.DecisionID]; held {
			entry.Components = row.Components
		}
	}

	out := make([]AuditedDecision, 0, len(ids))
	for _, id := range ids {
		if entry, held := gathered[id]; held {
			out = append(out, *entry)
		}
	}
	return out, int(total), nil
}
