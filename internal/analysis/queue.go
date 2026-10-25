// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// waitingClaim is whether a claim at the place of the finding under "f", in
// the product bound, waits for a second person. A lead somebody has already
// judged is not work for the next person to take.
var waitingClaim = `EXISTS (SELECT 1 FROM "decision" AS "dc"
	WHERE "dc"."product_id" = ? AND "dc"."live_key" IS NOT NULL
	  AND ` + finding.DecisionFiledAt("dc", "f") + `
	  AND "dc"."state" = '` + string(triage.Proposed) + `'
	  AND "dc"."needs_approval" = TRUE AND "dc"."sent_back_at" IS NULL)`

// Scope narrows a product's leads to one stream, one variant or one build.
// Unset is every one under the product.
type Scope struct {
	ProductID int64
	StreamID  *int64
	VariantID *int64
}

// QueueRow is one lead in a product: its place, and what the newest of its
// findings in the scope says about it.
type QueueRow struct {
	Place    string    `bun:"place_identity"`
	Rule     string    `bun:"rule"`
	Path     string    `bun:"path"`
	Line     *int      `bun:"start_line"`
	Function string    `bun:"enclosing"`
	Message  string    `bun:"message_text"`
	Stream   string    `bun:"stream"`
	Variant  string    `bun:"variant"`
	State    State     `bun:"stands"`
	Builds   int       `bun:"builds"`
	Opened   time.Time `bun:"opened"`
}

// Queue is one page of a product's leads, with how many the list holds in
// all and how many leads stand in each state.
type Queue struct {
	Rows  []QueueRow
	Total int
	// ByState counts the leads in each state, Waiting the open ones whose
	// claim waits for a second person, and Ruled the dismissed ones a
	// standing rule covers. A lead on two builds in two states counts in
	// both, and a lead seen twice in one state counts once.
	ByState map[State]int
	Waiting int
	Ruled   int
}

// LeadsOf is one page of the leads a product holds open where the subject
// may read them, one row per lead however many builds it is on.
//
// With no state named it is the queue: open leads nobody's claim waits on.
// Naming a state lists the leads in it, which is how the baseline is
// searched. Newest first.
func LeadsOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope, want State,
	limit, offset int) (*Queue, error) {

	visible, err := access.Readable(subject, scope.ProductID)
	if err != nil {
		return nil, err
	}
	perFinding := func() *bun.SelectQuery {
		state, stateArgs := stateOf(scope.ProductID)
		kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
		q := db.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
			Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
			Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
			Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
			ColumnExpr(`"f"."id", "f"."place_identity", "f"."opened_at"`).
			ColumnExpr(state+` AS "stands"`, stateArgs...).
			ColumnExpr(`CASE WHEN `+waitingClaim+` THEN 1 ELSE 0 END AS "awaits"`, scope.ProductID).
			ColumnExpr(`CASE WHEN `+ruled+` THEN 1 ELSE 0 END AS "covered"`, scope.ProductID).
			Where(`"s"."product_id" = ?`, scope.ProductID).
			Where(`"f"."closed_at" IS NULL`).
			Where(`"f"."visibility" IN (?)`, bun.List(visible)).
			Where(kinds, kindArgs...)
		if scope.StreamID != nil {
			q = q.Where(`"t"."stream_id" = ?`, *scope.StreamID)
		}
		if scope.VariantID != nil {
			q = q.Where(`"t"."variant_id" = ?`, *scope.VariantID)
		}
		return q
	}
	listed := func(q *bun.SelectQuery) *bun.SelectQuery {
		if want == "" {
			return q.Where(`"l"."stands" = ?`, string(Open)).Where(`"l"."awaits" = 0`)
		}
		return q.Where(`"l"."stands" = ?`, string(want))
	}

	out := &Queue{ByState: map[State]int{}}
	var counted []struct {
		State   State `bun:"stands"`
		Awaits  int   `bun:"awaits"`
		Covered int   `bun:"covered"`
		Leads   int   `bun:"leads"`
	}
	if err := db.NewSelect().TableExpr(`(?) AS "l"`, perFinding()).
		ColumnExpr(`"l"."stands", "l"."awaits", "l"."covered", COUNT(DISTINCT "l"."place_identity") AS "leads"`).
		GroupExpr(`"l"."stands", "l"."awaits", "l"."covered"`).
		Scan(ctx, &counted); err != nil {
		return nil, fmt.Errorf("count the leads of product %d: %w", scope.ProductID, err)
	}
	for _, c := range counted {
		out.ByState[c.State] += c.Leads
		if c.State == Open && c.Awaits == 1 {
			out.Waiting += c.Leads
		}
		if c.State == Dismissed && c.Covered == 1 {
			out.Ruled += c.Leads
		}
	}
	if err := listed(db.NewSelect().TableExpr(`(?) AS "l"`, perFinding())).
		ColumnExpr(`COUNT(DISTINCT "l"."place_identity")`).Scan(ctx, &out.Total); err != nil {
		return nil, fmt.Errorf("count the leads listed in product %d: %w", scope.ProductID, err)
	}

	var page []struct {
		Place  string    `bun:"place_identity"`
		Newest int64     `bun:"newest"`
		Builds int       `bun:"builds"`
		Opened time.Time `bun:"opened"`
	}
	if err := listed(db.NewSelect().TableExpr(`(?) AS "l"`, perFinding())).
		ColumnExpr(`"l"."place_identity", MAX("l"."id") AS "newest"`).
		ColumnExpr(`COUNT(*) AS "builds", MIN("l"."opened_at") AS "opened"`).
		GroupExpr(`"l"."place_identity"`).
		OrderExpr(`MIN("l"."opened_at") DESC, "l"."place_identity" ASC`).
		Limit(int64(limit)).Offset(int64(offset)).
		Scan(ctx, &page); err != nil {
		return nil, fmt.Errorf("read the leads of product %d: %w", scope.ProductID, err)
	}
	if len(page) == 0 {
		return out, nil
	}
	newest := make([]int64, len(page))
	for i, p := range page {
		newest[i] = p.Newest
	}
	state, stateArgs := stateOf(scope.ProductID)
	var rows []QueueRow
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		ColumnExpr(`"f"."place_identity", "vu"."identifier" AS "rule"`).
		ColumnExpr(`"ar"."path", "ar"."start_line", "ar"."enclosing", "ar"."message_text"`).
		ColumnExpr(`"s"."name" AS "stream", "va"."name" AS "variant"`).
		ColumnExpr(state+` AS "stands"`, stateArgs...).
		Where(`"f"."id" IN (?)`, bun.List(newest)).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what the leads of product %d say: %w", scope.ProductID, err)
	}
	byPlace := make(map[string]QueueRow, len(rows))
	for _, r := range rows {
		byPlace[r.Place] = r
	}
	out.Rows = make([]QueueRow, 0, len(page))
	for _, p := range page {
		r := byPlace[p.Place]
		r.Builds, r.Opened = p.Builds, p.Opened
		out.Rows = append(out.Rows, r)
	}
	return out, nil
}
