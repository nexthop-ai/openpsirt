// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// A page of claims, and everything the two lists that ask for one need.
//
// One act is one claim, so a page of work is a page of claims rather than of
// the rows underneath: a judgment covering four hundred places is one thing to
// read and one thing to decide about. What is paged is therefore the claim,
// ordered by its newest row, and the rows arrive afterwards in one read.
type claimPage struct {
	// Order is the claim identifiers in the order the page shows them.
	Order []int64
	// Claims is those claims, to look one up by identifier.
	Claims map[int64]Claim
	// Rows is every row of those claims this subject may read, oldest first,
	// which is the order the representative is taken in.
	Rows []Decision
	// Total is how many claims the whole selection holds, counted through the
	// same statement the page is read through.
	Total int
}

// pageClaims reads one page of the claims `claims` selects, and every row of
// them the subject may read.
//
// Written once because it was written twice, and the two copies had stopped
// agreeing about the thing that matters: one narrowed the rows it read by what
// the subject may see and the other did not. The second was safe for its own
// reason — it lists a claim only where no row of it is out of reach — but a
// guarantee that holds because of a clause in a different query is one that
// stops holding when that clause moves. The guard is applied here, once, for
// both.
//
// It is applied *as well as* whatever the selection did. A claim's rows need
// not agree about visibility, and a page listing a claim because one row was
// readable would otherwise count the undisclosed ones into the row, issue and
// place totals and could hand back one of them as the claim's representative,
// carrying its issue and its place. A count is the leak even where no row is
// shown.
//
// `what` names the list in a refusal — "what you proposed", "what is waiting"
// — because a failure reading a page says which page.
func (s *Store) pageClaims(ctx context.Context, subject access.Subject,
	claims func() *bun.SelectQuery, limit, offset int, what string) (claimPage, error) {

	out, err := s.claimsOn(ctx, claims, limit, offset, what)
	if err != nil || len(out.Order) == 0 {
		return out, err
	}
	rowsOf := readableBy(s.db.NewSelect().Model(&out.Rows).Relation("Claim").
		Where("de.claim_id IN (?)", bun.List(out.Order)), subject, "de")
	if err := rowsOf.Order("de.id ASC").Scan(ctx); err != nil {
		return out, fmt.Errorf("read %s: %w", what, err)
	}
	return out, nil
}

// claimsOn reads one page of the claims `claims` selects, and how many it
// selects, without their rows.
//
// The total rides on the page: `COUNT(*) OVER ()` is the number of claims the
// selection produced before the limit, which is what a second statement over
// the same selection would count. Where the page is empty — an offset past
// the end — no row carries it and it is counted on its own.
func (s *Store) claimsOn(ctx context.Context, claims func() *bun.SelectQuery,
	limit, offset int, what string) (claimPage, error) {

	var out claimPage
	var page []struct {
		ClaimID int64 `bun:"claim_id"`
		Newest  int64 `bun:"newest"`
		Total   int   `bun:"total"`
	}
	if err := claims().ColumnExpr(`COUNT(*) OVER () AS "total"`).OrderExpr("newest DESC").
		Limit(limit).Offset(offset).Scan(ctx, &page); err != nil {
		return out, fmt.Errorf("read %s: %w", what, err)
	}
	if len(page) == 0 {
		total, err := s.countClaims(ctx, claims, what)
		out.Total = total
		return out, err
	}
	out.Total = page[0].Total
	out.Order = make([]int64, 0, len(page))
	for _, row := range page {
		out.Order = append(out.Order, row.ClaimID)
	}

	var claimRows []Claim
	if err := s.db.NewSelect().Model(&claimRows).
		Where("id IN (?)", bun.List(out.Order)).Scan(ctx); err != nil {
		return out, fmt.Errorf("read %s: %w", what, err)
	}
	out.Claims = make(map[int64]Claim, len(claimRows))
	for _, claim := range claimRows {
		out.Claims[claim.ID] = claim
	}
	return out, nil
}

// countClaims is how many claims `claims` selects.
func (s *Store) countClaims(ctx context.Context, claims func() *bun.SelectQuery,
	what string) (int, error) {

	total, err := s.db.NewSelect().
		TableExpr(`(?) AS "page"`, claims()).Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count %s: %w", what, err)
	}
	return total, nil
}

// claimSizes is, for each claim, the earliest row of it the subject may read
// and how many rows, issues and places those rows cover — counted in the
// statement rather than by reading every row of every claim on the page. A
// claim over four hundred places is one card, and its card needs four numbers
// and one row.
//
// Narrowed by what the subject may read, for the reason pageClaims gives.
func (s *Store) claimSizes(ctx context.Context, subject access.Subject, ids []int64,
	what string) (map[int64]claimSize, error) {

	var counted []struct {
		ClaimID   int64 `bun:"claim_id"`
		Earliest  int64 `bun:"earliest"`
		Decisions int   `bun:"decisions"`
		Issues    int   `bun:"issues"`
		Places    int   `bun:"places"`
	}
	if err := readableBy(s.db.NewSelect().Model((*Decision)(nil)).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`MIN(de.id) AS "earliest"`).
		ColumnExpr(`COUNT(*) AS "decisions"`).
		ColumnExpr(`COUNT(DISTINCT de.vulnerability_id) AS "issues"`).
		ColumnExpr(`COUNT(DISTINCT de.place_identity) AS "places"`).
		Where("de.claim_id IN (?)", bun.List(ids)).
		GroupExpr("de.claim_id"), subject, "de").Scan(ctx, &counted); err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	if len(counted) == 0 {
		return map[int64]claimSize{}, nil
	}
	firsts := make([]int64, 0, len(counted))
	for _, row := range counted {
		firsts = append(firsts, row.Earliest)
	}
	var rows []Decision
	if err := s.db.NewSelect().Model(&rows).Relation("Claim").
		Where("de.id IN (?)", bun.List(firsts)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	byID := make(map[int64]Decision, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	out := make(map[int64]claimSize, len(counted))
	for _, row := range counted {
		out[row.ClaimID] = claimSize{First: byID[row.Earliest],
			Decisions: row.Decisions, Issues: row.Issues, Places: row.Places}
	}
	return out, nil
}

// claimSize is one claim's representative row and how much it covers.
type claimSize struct {
	First                     Decision
	Decisions, Issues, Places int
}
