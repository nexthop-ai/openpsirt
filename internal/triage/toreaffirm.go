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

// ToReaffirm is one decision of somebody's that lapsed and that nothing has
// replaced: work handed back to them.
type ToReaffirm struct {
	Decision Decision
	// DecisionOccurrence is a representative lapsed row — the earliest — and Reasoning
	// is what the decision rested on.
	DecisionOccurrence DecisionOccurrence
	Reasoning          string
	// Rows, Issues and Occurrences count the lapsed rows, in the three units a
	// queue card uses.
	Rows, Issues, Occurrences int
	LapsedAt                  *time.Time
	// CodeMoved says a version moved under at least one row. RatedWorse says
	// the issue now sits in a higher band than it did when the decision was made,
	// on a decision a severity bears on. Both can hold.
	CodeMoved  bool
	RatedWorse bool
	// Was and Now are how bad the issue was judged to be when the decision was
	// made and how bad it is judged to be here now: for the first row rated
	// worse where one was, and for the representative row otherwise.
	Was, Now int
}

// decidableBy narrows a query to the rows a subject may argue about,
// including the cases they were brought into.
func decidableBy(query *bun.SelectQuery, subject access.Subject, column string) *bun.SelectQuery {
	return narrowedBy(query, subject, column, mayDecide, onCases)
}

// ToReaffirm lists the decisions this person made that lapsed and that nothing
// has replaced, the most recently written first, in one product where one is
// named.
//
// Only what they may still re-affirm: their own decisions, whose rows they may
// still argue about. Why each lapsed is worked out from what is there now
// rather than stored: a version that no longer matches anything open, and a
// rating in a higher band than the decision was made against, are both facts
// about the present that anybody can check.
func (s *Store) ToReaffirm(ctx context.Context, subject access.Subject, productID int64,
	limit, offset int) ([]ToReaffirm, int, error) {

	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read what is yours to re-affirm")
	}
	limit = database.AList.Of(limit)

	mine := func() *bun.SelectQuery {
		q := s.yoursToReaffirm(subject).
			ColumnExpr(`"de"."decision_id" AS "decision_id"`).
			ColumnExpr(`MAX("de"."id") AS "newest"`).
			GroupExpr(`"de"."decision_id"`)
		if productID > 0 {
			q = q.Where(`"de"."product_id" = ?`, productID)
		}
		return q
	}
	page, err := s.pageDecisions(ctx, subject, mine, limit, offset, "what is yours to re-affirm")
	if err != nil {
		return nil, 0, err
	}
	if len(page.Order) == 0 {
		return nil, page.Total, nil
	}

	// The rows a re-affirmation re-makes, so a code finding past its end of life is
	// not counted.
	inSupport, supportArgs := finding.CodeFindingInSupport(`"de"."product_id"`, `"de"."occurrence_identity"`, s.now())
	var latest []int64
	if err := stillLatest(s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
		ColumnExpr(`"de"."id"`).
		Where(`"de"."decision_id" IN (?)`, bun.List(page.Order)).
		Where(`"de"."state" = ?`, LapsedState)).
		Where(inSupport, supportArgs...).
		Scan(ctx, &latest); err != nil {
		return nil, 0, fmt.Errorf("read what is yours to re-affirm: %w", err)
	}
	wanted := make(map[int64]bool, len(latest))
	for _, id := range latest {
		wanted[id] = true
	}

	gathered := map[int64]*ToReaffirm{}
	issues := map[int64]map[int64]bool{}
	occurrences := map[int64]map[string]bool{}
	var lapsedRows []DecisionOccurrence
	for _, row := range page.Rows {
		if !wanted[row.ID] {
			continue
		}
		lapsedRows = append(lapsedRows, row)
		entry, seen := gathered[row.DecisionID]
		if !seen {
			entry = &ToReaffirm{Decision: page.Decisions[row.DecisionID], DecisionOccurrence: row}
			gathered[row.DecisionID] = entry
			issues[row.DecisionID] = map[int64]bool{}
			occurrences[row.DecisionID] = map[string]bool{}
		}
		entry.Rows++
		issues[row.DecisionID][row.VulnerabilityID] = true
		occurrences[row.DecisionID][row.OccurrenceIdentity] = true
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
		entry := gathered[row.DecisionID]
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
		if !entry.RatedWorse && turnsOnSeverity(entry.Decision) &&
			ratedWorse(row.SeverityCenti, severity[key]) {
			entry.RatedWorse = true
			entry.Was, entry.Now = orZeroCenti(row.SeverityCenti), severity[key]
		}
	}

	representatives := make([]DecisionOccurrence, 0, len(gathered))
	for _, id := range page.Order {
		if entry, ok := gathered[id]; ok {
			representatives = append(representatives, entry.DecisionOccurrence)
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
		entry.Occurrences = len(occurrences[id])
		entry.Reasoning = reasoning[entry.DecisionOccurrence.ID]
		if !entry.RatedWorse {
			entry.Was = orZeroCenti(entry.DecisionOccurrence.SeverityCenti)
			entry.Now = severity[[2]int64{entry.DecisionOccurrence.ProductID, entry.DecisionOccurrence.VulnerabilityID}]
		}
		out = append(out, *entry)
	}
	return out, page.Total, nil
}

// yoursToReaffirm selects the lapsed rows, nothing having replaced them, of
// the decisions this subject made and may re-affirm, over decision_occurrence AS "de".
//
// A row at a code finding past its end of life is left off, and so is a decision holding
// no other: re-affirming re-makes a decision at its other occurrences, and refuses one
// with none.
func (s *Store) yoursToReaffirm(subject access.Subject) *bun.SelectQuery {
	inSupport, args := finding.CodeFindingInSupport(`"de"."product_id"`, `"de"."occurrence_identity"`, s.now())
	return s.lapsedOfYours(subject).Where(inSupport, args...)
}

// lapsedOfYours is yoursToReaffirm wherever the occurrences are.
//
// A decision with any lapsed row out of the subject's reach is left off:
// re-affirming acts on the whole decision, and would refuse it. So is a decision
// with a withdrawn row: its author took it back, and a withdrawal leaves a
// row that had already lapsed as it was.
func (s *Store) lapsedOfYours(subject access.Subject) *bun.SelectQuery {
	outOfReach, reachArgs := notDecidableWhere(subject, "dn")
	q := stillLatest(s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		Where(`"cl"."proposed_by" = ?`, subject.ID).
		Where(`"de"."state" = ?`, LapsedState)).
		Where(`NOT EXISTS (SELECT 1 FROM "decision_occurrence" AS "dw" WHERE "dw"."decision_id" = "de"."decision_id"`+
			` AND "dw"."state" = ?)`, Withdrawn).
		Where(`NOT EXISTS (SELECT 1 FROM "decision_occurrence" AS "dn" WHERE "dn"."decision_id" = "de"."decision_id"`+
			` AND "dn"."state" = ? AND `+outOfReach+`)`,
			append([]any{LapsedState}, reachArgs...)...)
	return decidableBy(q, subject, "de")
}

// Reaffirmable reports whether this subject may re-affirm the decision now: it is
// theirs, it lapsed, and nothing has replaced it.
func (s *Store) Reaffirmable(ctx context.Context, subject access.Subject, decisionID int64) (bool, error) {
	if subject.Kind != access.Person {
		return false, nil
	}
	found, err := s.yoursToReaffirm(subject).Where(`"de"."decision_id" = ?`, decisionID).Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether this is yours to re-affirm: %w", err)
	}
	return found, nil
}

// movedUnder reports which lapsed rows no open finding in their product still
// matches at the versions they were made against: the code moved.
func (s *Store) movedUnder(ctx context.Context, rows []DecisionOccurrence) (map[int64]bool, error) {
	moved := map[int64]bool{}
	if len(rows) == 0 {
		return moved, nil
	}
	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	kinds, args := kindsOf(kind.VersionCarry, "f")
	var still []int64
	if err := s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
		ColumnExpr(`"de"."id"`).
		Where(`"de"."id" IN (?)`, bun.List(ids)).
		Where(`EXISTS (SELECT 1 FROM "finding" AS "f"`+
			` JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`+
			` LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`+
			` JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`+
			` JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`+
			` WHERE "st"."product_id" = "de"."product_id" AND "f"."closed_at" IS NULL`+
			` AND `+kinds+
			` AND `+finding.DecisionOccurrenceFiledAt("de", "f")+` AND `+finding.VersionsMatch+`)`, args...).
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
