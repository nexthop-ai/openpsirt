// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// A page of decisions, and everything the two lists that ask for one need.
//
// One act is one decision, so a page of work is a page of decisions rather than of
// the rows underneath: a decision covering four hundred occurrences is one thing to
// read and one thing to decide about. What is paged is therefore the decision,
// ordered by its newest row, and the rows arrive afterwards in one read.
type decisionPage struct {
	// Order is the decision identifiers in the order the page shows them.
	Order []int64
	// Decisions is those decisions, to look one up by identifier.
	Decisions map[int64]Decision
	// Rows is every row of those decisions this subject may read, oldest first,
	// which is the order the representative is taken in.
	Rows []DecisionOccurrence
	// Total is how many decisions the whole selection holds, counted through the
	// same statement the page is read through.
	Total int
}

// pageDecisions reads one page of the decisions `decisions` selects, and every row of
// them the subject may read.
//
// Written once because it was written twice, and the two copies had stopped
// agreeing about the thing that matters: one narrowed the rows it read by what
// the subject may see and the other did not. The second was safe for its own
// reason — it lists a decision only where no row of it is out of reach — but a
// guarantee that holds because of a clause in a different query is one that
// stops holding when that clause moves. The guard is applied here, once, for
// both.
//
// It is applied *as well as* whatever the selection did. A decision's rows need
// not agree about visibility, and a page listing a decision because one row was
// readable would otherwise count the undisclosed ones into the row, issue and
// occurrence totals and could hand back one of them as the decision's representative,
// carrying its issue and its occurrence. A count is the leak even where no row is
// shown.
//
// `what` names the list in a refusal — "what you proposed", "what is waiting"
// — because a failure reading a page says which page.
func (s *Store) pageDecisions(ctx context.Context, subject access.Subject,
	decisions func() *bun.SelectQuery, limit, offset int, what string) (decisionPage, error) {

	out, err := s.decisionsOn(ctx, decisions, limit, offset, what)
	if err != nil || len(out.Order) == 0 {
		return out, err
	}
	rowsOf := readableBy(s.db.NewSelect().Model(&out.Rows).Relation("Decision").
		Where(`"de"."decision_id" IN (?)`, bun.List(out.Order)), subject, "de")
	if err := rowsOf.Order("de.id ASC").Scan(ctx); err != nil {
		return out, fmt.Errorf("read %s: %w", what, err)
	}
	return out, nil
}

// decisionsOn reads one page of the decisions `decisions` selects, and how many it
// selects, without their rows.
//
// The total rides on the page: `COUNT(*) OVER ()` is the number of decisions the
// selection produced before the limit, which is what a second statement over
// the same selection would count. Where the page is empty — an offset past
// the end — no row carries it and it is counted on its own.
func (s *Store) decisionsOn(ctx context.Context, decisions func() *bun.SelectQuery,
	limit, offset int, what string) (decisionPage, error) {

	var out decisionPage
	var page []struct {
		DecisionID int64 `bun:"decision_id"`
		Newest     int64 `bun:"newest"`
		Total      int   `bun:"total"`
	}
	if err := decisions().ColumnExpr(`COUNT(*) OVER () AS "total"`).OrderExpr("newest DESC").
		Limit(int64(limit)).Offset(int64(offset)).Scan(ctx, &page); err != nil {
		return out, fmt.Errorf("read %s: %w", what, err)
	}
	if len(page) == 0 {
		total, err := s.countDecisions(ctx, decisions, what)
		out.Total = total
		return out, err
	}
	out.Total = page[0].Total
	out.Order = make([]int64, 0, len(page))
	for _, row := range page {
		out.Order = append(out.Order, row.DecisionID)
	}

	var decisionRows []Decision
	if err := s.db.NewSelect().Model(&decisionRows).
		Where(`"id" IN (?)`, bun.List(out.Order)).Scan(ctx); err != nil {
		return out, fmt.Errorf("read %s: %w", what, err)
	}
	out.Decisions = make(map[int64]Decision, len(decisionRows))
	for _, decision := range decisionRows {
		out.Decisions[decision.ID] = decision
	}
	return out, nil
}

// countDecisions is how many decisions `decisions` selects.
func (s *Store) countDecisions(ctx context.Context, decisions func() *bun.SelectQuery,
	what string) (int, error) {

	total, err := s.db.NewSelect().
		TableExpr(`(?) AS "page"`, decisions()).Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count %s: %w", what, err)
	}
	return int(total), nil
}

// decisionSizes is, for each decision, the earliest row of it the subject may read
// and how many rows, issues and occurrences those rows cover — counted in the
// statement rather than by reading every row of every decision on the page. A
// decision over four hundred occurrences is one card, and its card needs four numbers
// and one row.
//
// Narrowed by what the subject may read, for the reason pageDecisions gives.
func (s *Store) decisionSizes(ctx context.Context, subject access.Subject, ids []int64,
	what string) (map[int64]decisionSize, error) {

	var counted []struct {
		DecisionID  int64 `bun:"decision_id"`
		Earliest    int64 `bun:"earliest"`
		Rows        int   `bun:"decisions"`
		Issues      int   `bun:"issues"`
		Occurrences int   `bun:"places"`
	}
	if err := readableBy(s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`MIN("de"."id") AS "earliest"`).
		ColumnExpr(`COUNT(*) AS "decisions"`).
		ColumnExpr(`COUNT(DISTINCT "de"."vulnerability_id") AS "issues"`).
		ColumnExpr(`COUNT(DISTINCT "de"."occurrence_identity") AS "places"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(ids)).
		GroupExpr(`"de"."decision_id"`), subject, "de").Scan(ctx, &counted); err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	if len(counted) == 0 {
		return map[int64]decisionSize{}, nil
	}
	firsts := make([]int64, 0, len(counted))
	for _, row := range counted {
		firsts = append(firsts, row.Earliest)
	}
	var rows []DecisionOccurrence
	if err := s.db.NewSelect().Model(&rows).Relation("Decision").
		Where(`"de"."id" IN (?)`, bun.List(firsts)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	byID := make(map[int64]DecisionOccurrence, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	out := make(map[int64]decisionSize, len(counted))
	for _, row := range counted {
		out[row.DecisionID] = decisionSize{First: byID[row.Earliest],
			Rows: row.Rows, Issues: row.Issues, Occurrences: row.Occurrences}
	}
	return out, nil
}

// decisionSize is one decision's representative row and how much it covers.
type decisionSize struct {
	First                     DecisionOccurrence
	Rows, Issues, Occurrences int
}
