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

// pageClaims reads one page of the claims `claims` selects.
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

	var out claimPage
	total, err := s.db.NewSelect().
		TableExpr(`(?) AS "page"`, claims()).Count(ctx)
	if err != nil {
		return out, fmt.Errorf("count %s: %w", what, err)
	}
	out.Total = total

	var page []struct {
		ClaimID int64 `bun:"claim_id"`
		Newest  int64 `bun:"newest"`
	}
	if err := claims().OrderExpr("newest DESC").
		Limit(limit).Offset(offset).Scan(ctx, &page); err != nil {
		return out, fmt.Errorf("read %s: %w", what, err)
	}
	if len(page) == 0 {
		return out, nil
	}
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

	rowsOf := readableBy(s.db.NewSelect().Model(&out.Rows).Relation("Claim").
		Where("de.claim_id IN (?)", bun.List(out.Order)), subject, "de")
	if err := rowsOf.Order("de.id ASC").Scan(ctx); err != nil {
		return out, fmt.Errorf("read %s: %w", what, err)
	}
	return out, nil
}
