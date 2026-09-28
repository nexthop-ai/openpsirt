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

// ToReaffirm is one claim of somebody's that lapsed and that nothing has
// replaced: work handed back to them.
type ToReaffirm struct {
	Claim Claim
	// Decision is a representative lapsed row — the earliest — and Reasoning
	// is what the claim rested on.
	Decision  Decision
	Reasoning string
	// Rows, Issues and Places count the lapsed rows, in the three units a
	// queue card uses.
	Rows, Issues, Places int
	LapsedAt             *time.Time
	// CodeMoved says a version moved under at least one row. RatedWorse says
	// the issue now sits in a higher band than it did when the claim was made,
	// on a claim a severity bears on. Both can hold.
	CodeMoved  bool
	RatedWorse bool
	// Was and Now are how bad the issue was judged to be when the claim was
	// made and how bad it is judged to be here now: for the first row rated
	// worse where one was, and for the representative row otherwise.
	Was, Now int
}

// decidableBy narrows a query to the decisions a subject may argue about,
// including the cases they were brought into.
func decidableBy(query *bun.SelectQuery, subject access.Subject, column string) *bun.SelectQuery {
	return narrowedBy(query, subject, column, mayDecide, onCases)
}

// ToReaffirm lists the claims this person made that lapsed and that nothing
// has replaced, the most recently written first, in one product where one is
// named.
//
// Only what they may still re-affirm: their own claims, whose rows they may
// still argue about. Why each lapsed is worked out from what is there now
// rather than stored: a version that no longer matches anything open, and a
// rating in a higher band than the claim was made against, are both facts
// about the present that anybody can check.
func (s *Store) ToReaffirm(ctx context.Context, subject access.Subject, productID int64,
	limit, offset int) ([]ToReaffirm, int, error) {

	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read what is yours to re-affirm")
	}
	limit = database.AList.Of(limit)

	mine := func() *bun.SelectQuery {
		q := s.yoursToReaffirm(subject).
			ColumnExpr(`de.claim_id AS "claim_id"`).
			ColumnExpr(`MAX(de.id) AS "newest"`).
			GroupExpr("de.claim_id")
		if productID > 0 {
			q = q.Where("de.product_id = ?", productID)
		}
		return q
	}
	page, err := s.pageClaims(ctx, subject, mine, limit, offset, "what is yours to re-affirm")
	if err != nil {
		return nil, 0, err
	}
	if len(page.Order) == 0 {
		return nil, page.Total, nil
	}

	var latest []int64
	if err := stillLatest(s.db.NewSelect().Model((*Decision)(nil)).
		ColumnExpr("de.id").
		Where("de.claim_id IN (?)", bun.List(page.Order)).
		Where("de.state = ?", LapsedState)).
		Scan(ctx, &latest); err != nil {
		return nil, 0, fmt.Errorf("read what is yours to re-affirm: %w", err)
	}
	wanted := make(map[int64]bool, len(latest))
	for _, id := range latest {
		wanted[id] = true
	}

	gathered := map[int64]*ToReaffirm{}
	issues := map[int64]map[int64]bool{}
	places := map[int64]map[string]bool{}
	var lapsedRows []Decision
	for _, row := range page.Rows {
		if !wanted[row.ID] {
			continue
		}
		lapsedRows = append(lapsedRows, row)
		entry, seen := gathered[row.ClaimID]
		if !seen {
			entry = &ToReaffirm{Claim: page.Claims[row.ClaimID], Decision: row}
			gathered[row.ClaimID] = entry
			issues[row.ClaimID] = map[int64]bool{}
			places[row.ClaimID] = map[string]bool{}
		}
		entry.Rows++
		issues[row.ClaimID][row.VulnerabilityID] = true
		places[row.ClaimID][row.PlaceIdentity] = true
		if row.EndedAt != nil && (entry.LapsedAt == nil || row.EndedAt.After(*entry.LapsedAt)) {
			entry.LapsedAt = row.EndedAt
		}
	}

	moved, err := s.movedUnder(ctx, lapsedRows)
	if err != nil {
		return nil, 0, err
	}
	severity := map[[2]int64]int{}
	for _, row := range lapsedRows {
		entry := gathered[row.ClaimID]
		if moved[row.ID] {
			entry.CodeMoved = true
		}
		key := [2]int64{row.ProductID, row.VulnerabilityID}
		if _, asked := severity[key]; !asked {
			now, err := s.severityOf(ctx, row.ProductID, row.VulnerabilityID)
			if err != nil {
				return nil, 0, err
			}
			severity[key] = now
		}
		if !entry.RatedWorse && turnsOnSeverity(entry.Claim) &&
			ratedWorse(row.SeverityCenti, severity[key]) {
			entry.RatedWorse = true
			entry.Was, entry.Now = orZeroCenti(row.SeverityCenti), severity[key]
		}
	}

	representatives := make([]Decision, 0, len(gathered))
	for _, id := range page.Order {
		if entry, ok := gathered[id]; ok {
			representatives = append(representatives, entry.Decision)
		}
	}
	reasoning, err := s.currentReasoning(ctx, representatives)
	if err != nil {
		return nil, 0, err
	}

	out := make([]ToReaffirm, 0, len(gathered))
	for _, id := range page.Order {
		entry, ok := gathered[id]
		if !ok {
			continue
		}
		entry.Issues = len(issues[id])
		entry.Places = len(places[id])
		entry.Reasoning = reasoning[entry.Decision.ID]
		if !entry.RatedWorse {
			entry.Was = orZeroCenti(entry.Decision.SeverityCenti)
			entry.Now = severity[[2]int64{entry.Decision.ProductID, entry.Decision.VulnerabilityID}]
		}
		out = append(out, *entry)
	}
	return out, page.Total, nil
}

// yoursToReaffirm selects the lapsed rows, nothing having replaced them, of
// the claims this subject made and may re-affirm, over decision AS "de".
//
// A claim with any lapsed row out of the subject's reach is left off:
// re-affirming acts on the whole claim, and would refuse it. So is a claim
// with a withdrawn row: its author took it back, and a withdrawal leaves a
// row that had already lapsed as it was.
func (s *Store) yoursToReaffirm(subject access.Subject) *bun.SelectQuery {
	outOfReach, reachArgs := notDecidableWhere(subject, "dn")
	q := stillLatest(s.db.NewSelect().Model((*Decision)(nil)).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		Where("cl.proposed_by = ?", subject.ID).
		Where("de.state = ?", LapsedState)).
		Where(`NOT EXISTS (SELECT 1 FROM "decision" AS "dw" WHERE dw.claim_id = de.claim_id`+
			` AND dw.state = ?)`, Withdrawn).
		Where(`NOT EXISTS (SELECT 1 FROM "decision" AS "dn" WHERE dn.claim_id = de.claim_id`+
			` AND dn.state = ? AND `+outOfReach+`)`,
			append([]any{LapsedState}, reachArgs...)...)
	return decidableBy(q, subject, "de")
}

// Reaffirmable reports whether this subject may re-affirm the claim now: it is
// theirs, it lapsed, and nothing has replaced it.
func (s *Store) Reaffirmable(ctx context.Context, subject access.Subject, claimID int64) (bool, error) {
	if subject.Kind != access.Person {
		return false, nil
	}
	found, err := s.yoursToReaffirm(subject).Where("de.claim_id = ?", claimID).Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether this is yours to re-affirm: %w", err)
	}
	return found, nil
}

// movedUnder reports which lapsed rows no open finding in their product still
// matches at the versions they were made against: the code moved.
func (s *Store) movedUnder(ctx context.Context, rows []Decision) (map[int64]bool, error) {
	moved := map[int64]bool{}
	if len(rows) == 0 {
		return moved, nil
	}
	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	matching := "COALESCE(de.component_upstream_version, '') = " + finding.ComponentUpstreamExpr +
		" AND COALESCE(de.consumer_upstream_version, '') = " + finding.ConsumerUpstreamExpr
	var still []int64
	if err := s.db.NewSelect().Model((*Decision)(nil)).
		ColumnExpr("de.id").
		Where("de.id IN (?)", bun.List(ids)).
		Where(`EXISTS (SELECT 1 FROM "finding" AS "f"`+
			` JOIN "component" AS "c" ON c.id = f.component_id`+
			` LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`+
			` JOIN "target" AS "tg" ON tg.id = f.target_id`+
			` JOIN "stream" AS "st" ON st.id = tg.stream_id`+
			` WHERE st.product_id = de.product_id AND f.closed_at IS NULL`+
			` AND f.vulnerability_id = de.vulnerability_id`+
			` AND f.place_identity = de.place_identity AND `+matching+`)`).
		Scan(ctx, &still); err != nil {
		return nil, fmt.Errorf("read which of these the code moved under: %w", err)
	}
	stands := make(map[int64]bool, len(still))
	for _, id := range still {
		stands[id] = true
	}
	for _, id := range ids {
		if !stands[id] {
			moved[id] = true
		}
	}
	return moved, nil
}

// orZeroCenti is a baseline that may not be recorded, as a number.
func orZeroCenti(centi *int) int {
	if centi == nil {
		return 0
	}
	return *centi
}
