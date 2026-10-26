// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
)

// waitingClaim is whether a claim at the place of the finding under "f", in
// the product bound, waits for a second person. A lead somebody has already
// judged is not work for the next person to take.
var waitingClaim = `EXISTS (SELECT 1 FROM "decision" AS "dc"
	WHERE "dc"."product_id" = ? AND "dc"."live_key" IS NOT NULL
	  AND ` + finding.DecisionFiledAt("dc", "f") + `
	  AND "dc"."state" = '` + string(triage.Proposed) + `'
	  AND "dc"."needs_approval" = TRUE AND "dc"."sent_back_at" IS NULL)`

// precisionRank is the tool's precision of the rule of the finding under "f",
// whose rating is under "rr", as a number that sorts the most precise first,
// and nought where the tool gives none.
var precisionRank = func() string {
	out := `CASE "rr"."precision"`
	for i, p := range finding.Precisions() {
		out += ` WHEN '` + p + `' THEN ` + strconv.Itoa(len(finding.Precisions())-i)
	}
	return out + ` ELSE 0 END`
}()

// Scope narrows a product's leads to one stream, one variant or one build,
// and to one analyzer series. Unset is every one under the product.
type Scope struct {
	ProductID int64
	StreamID  *int64
	VariantID *int64
	// Series is a series' name, matched without regard to capitals. A name
	// no series of the product holds lists nothing.
	Series string
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
	// Holder is the party dealing with the lead on that build, where anybody
	// is: a person, or a team it is queued with.
	Holder *int64 `bun:"assigned_to"`
	// Stub is a lead moved into a case, read without what the analyzer said
	// or who holds it.
	Stub bool `bun:"-"`
	// ThirdParty says the lead is under a path the newest run that saw it
	// declared as third-party code, as its evidence says.
	ThirdParty bool `bun:"-"`
	// Declared is that run's list of third-party paths, as it is stored.
	Declared string `bun:"third_party"`
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
	// Ended is the open leads the queue leaves out because every release
	// they were seen in is past its end of life.
	Ended int
}

// LeadsOf is one page of a product's leads where the subject may read them,
// one row per lead however many builds it is on.
//
// With no state named it is the queue: open leads nobody's claim waits on.
// Naming a state lists the leads in it, which is how the baseline is
// searched. A fixed lead is one closed on a build, and listed there until the
// lead opens anew at its place on that build. Ordered by what is likely real: the rank of the weaknesses the
// rule names, whether another analyzer reports the same flaw, the tool's own
// security severity for the rule, its precision, then newest first.
func LeadsOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope, want State,
	limit, offset int) (*Queue, error) {

	visible, err := access.Readable(subject, scope.ProductID)
	if err != nil {
		return nil, err
	}
	perFinding := func() *bun.SelectQuery { return leadFindings(db, subject, scope, visible) }

	// A sighting in a release past its end of life is no work for anybody,
	// so the queue counts none of them, and a lead open only there leaves
	// the queue though it may still be decided where it is seen elsewhere.
	// The lists by state still show it.
	ended, err := catalog.NewStore(db).StreamsPastEndOfLife(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	queued := func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.Where(`"l"."stands" = ?`, string(Open)).Where(`"l"."awaits" = 0`)
	}
	listed := func(q *bun.SelectQuery) *bun.SelectQuery {
		if want != "" {
			return q.Where(`"l"."stands" = ?`, string(want))
		}
		if len(ended) > 0 {
			q = q.Where(`"l"."stream_id" NOT IN (?)`, bun.List(ended))
		}
		return queued(q)
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
	if want == "" && len(ended) > 0 {
		var all int
		if err := queued(db.NewSelect().TableExpr(`(?) AS "l"`, perFinding())).
			ColumnExpr(`COUNT(DISTINCT "l"."place_identity")`).Scan(ctx, &all); err != nil {
			return nil, fmt.Errorf("count the leads of product %d past their end of life: %w", scope.ProductID, err)
		}
		out.Ended = all - out.Total
	}

	var page []struct {
		Place  string    `bun:"place_identity"`
		Newest int64     `bun:"newest"`
		Builds int       `bun:"builds"`
		Opened time.Time `bun:"opened"`
		Stub   int       `bun:"stub"`
	}
	if err := listed(db.NewSelect().TableExpr(`(?) AS "l"`, perFinding())).
		ColumnExpr(`"l"."place_identity", MAX("l"."id") AS "newest"`).
		// Builds rather than rows: a lead fixed, seen again and fixed again
		// on one build is two closed rows there.
		ColumnExpr(`COUNT(DISTINCT "l"."target_id") AS "builds", MIN("l"."opened_at") AS "opened"`).
		ColumnExpr(`MIN("l"."stub") AS "stub"`).
		GroupExpr(`"l"."place_identity"`).
		OrderExpr(`MAX("l"."tier") DESC, MAX("l"."corroborated") DESC`).
		OrderExpr(`MAX("l"."severity") DESC, MAX("l"."precise") DESC`).
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
		ColumnExpr(`"s"."name" AS "stream", "va"."name" AS "variant", "f"."assigned_to"`).
		// A finding has one sighting, and its last run is the run the evidence
		// reads.
		Join(`JOIN "series_run" AS "sr" ON "sr"."id" = "si"."last_run_id"`).
		ColumnExpr(state+` AS "stands"`, stateArgs...).
		ColumnExpr(`"sr"."third_party"`).
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
		r.ThirdParty = declaredIn(r.Declared, r.Path) != ""
		// What the analyzer said, and who is working it, are the case's
		// once the lead is moved.
		if p.Stub == 1 {
			r.Message, r.Holder, r.Stub = "", nil, true
		}
		out.Rows = append(out.Rows, r)
	}
	return out, nil
}

// leadFindings is every finding of a lead in the scope that the subject may
// read, one row per finding: the lead's place, its build, its series, where it
// stands, whether a claim waits on it, whether a standing rule covers it, and
// what the queue orders it by.
//
// The product's own visibilities, and a moved lead as a stub. A lead granted
// one at a time is reached through its evidence, never a list. A finding
// closed on a build is read until the lead opens anew at its place there.
func leadFindings(db bun.IDB, subject access.Subject, scope Scope, visible []access.Visibility) *bun.SelectQuery {
	reach := finding.LeadReach(subject, scope.ProductID)
	state, stateArgs := stateOf(scope.ProductID)
	kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
	q := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
		Join(`LEFT JOIN "rule_rating" AS "rr" ON "rr"."vulnerability_id" = "f"."vulnerability_id"`).
		ColumnExpr(`"f"."id", "f"."place_identity", "f"."target_id", "f"."opened_at", "si"."series_id", "t"."stream_id"`).
		ColumnExpr(`COALESCE("rr"."weakness_tier", 0) AS "tier"`).
		ColumnExpr(`CASE WHEN `+corroborated+` THEN 1 ELSE 0 END AS "corroborated"`).
		ColumnExpr(`COALESCE("rr"."severity_tenths", -1) AS "severity"`).
		ColumnExpr(precisionRank+` AS "precise"`).
		ColumnExpr(state+` AS "stands"`, stateArgs...).
		ColumnExpr(`CASE WHEN `+waitingClaim+` THEN 1 ELSE 0 END AS "awaits"`, scope.ProductID).
		ColumnExpr(`CASE WHEN `+ruled+` THEN 1 ELSE 0 END AS "covered"`, scope.ProductID).
		Where(`"s"."product_id" = ?`, scope.ProductID).
		Where(`("f"."closed_at" IS NULL OR NOT EXISTS (SELECT 1 FROM "finding" AS "fo"
			WHERE "fo"."place_identity" = "f"."place_identity" AND "fo"."target_id" = "f"."target_id"
			  AND "fo"."closed_at" IS NULL))`).
		ColumnExpr(`CASE WHEN "f"."visibility" IN (?) THEN 0 ELSE 1 END AS "stub"`, bun.List(visible)).
		Where(`("f"."visibility" IN (?) OR `+reach.Stub+`)`, append([]any{bun.List(visible)}, reach.StubArgs...)...).
		Where(kinds, kindArgs...)
	if scope.StreamID != nil {
		q = q.Where(`"t"."stream_id" = ?`, *scope.StreamID)
	}
	if scope.VariantID != nil {
		q = q.Where(`"t"."variant_id" = ?`, *scope.VariantID)
	}
	if scope.Series != "" {
		named, namedArgs := kind.Leads.Where(`"sn"."kind"`)
		q = q.Where(`"si"."series_id" IN (SELECT "sn"."id" FROM "series" AS "sn"
			WHERE "sn"."product_id" = ? AND "sn"."name_folded" = ? AND `+named+`)`,
			append([]any{scope.ProductID, typedname.Matching(scope.Series)}, namedArgs...)...)
	}
	return q
}
