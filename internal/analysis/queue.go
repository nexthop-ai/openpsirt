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

// waitingDecision is whether a decision at the occurrence of the finding under "f", in
// the product bound, waits for a second person. A code finding somebody has already
// judged is not work for the next person to take.
var waitingDecision = `EXISTS (SELECT 1 FROM "decision_occurrence" AS "dc"
	WHERE "dc"."product_id" = ? AND "dc"."live_key" IS NOT NULL
	  AND ` + finding.DecisionOccurrenceFiledAt("dc", "f") + `
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

// Scope narrows a product's leads to one branch or tag, one variant or one build,
// and to one analyzer series. Unset is every one under the product.
type Scope struct {
	ProductID     int64
	BranchOrTagID *int64
	VariantID     *int64
	// Series is a series' name, matched without regard to capitals. A name
	// no series of the product holds lists nothing.
	Series string
	// Unassigned keeps the code findings nobody holds on the build a row names.
	Unassigned bool
	// Method keeps the code findings one testing method reported. Empty, every
	// method.
	Method Method
}

// Method is a way of testing our own code, by the word people search for it
// under.
type Method string

// SAST is static analysis: an analyzer reading the source.
const SAST Method = "sast"

// methodKinds is the kind of finding each method records.
var methodKinds = map[Method]kind.Kind{SAST: kind.Analysis}

// Methods is every method the code finding queue narrows by, in the order a
// filter offers them.
func Methods() []string { return []string{string(SAST)} }

// CodeFindingAssignees is every word the code finding queue asks who holds a code finding in: the
// findings list's word for work nobody holds.
func CodeFindingAssignees() []string { return []string{finding.HeldByNobody} }

// QueueRow is one code finding in a product: its occurrence, and what the newest of its
// findings in the scope says about it.
type QueueRow struct {
	Occurrence  string    `bun:"occurrence_identity"`
	Rule        string    `bun:"rule"`
	Path        string    `bun:"path"`
	Line        *int      `bun:"start_line"`
	Function    string    `bun:"enclosing"`
	Message     string    `bun:"message_text"`
	BranchOrTag string    `bun:"branch_or_tag"`
	Variant     string    `bun:"variant"`
	State       State     `bun:"stands"`
	Builds      int       `bun:"builds"`
	Opened      time.Time `bun:"opened"`
	// Holder is the party dealing with the code finding on that build, where anybody
	// is: a person, or a team it is queued with.
	Holder *int64 `bun:"assigned_to"`
	// ThirdParty says the code finding is under a path the newest run that saw it
	// declared as third-party code, as its evidence says.
	ThirdParty bool `bun:"-"`
	// Declared is that run's list of third-party paths, as it is stored.
	Declared string `bun:"third_party"`
}

// Queue is one page of a product's code findings, with how many the list holds in
// all and how many code findings stand in each state.
type Queue struct {
	Rows  []QueueRow
	Total int
	// ByState counts the code findings in each state, Waiting the open ones whose
	// decision waits for a second person, and Ruled the dismissed ones a
	// suppression rule covers. A code finding on two builds in two states counts in
	// both, and a code finding seen twice in one state counts once.
	ByState map[State]int
	Waiting int
	Ruled   int
	// Ended is the open code findings the queue leaves out because every release
	// they were seen in is past its end of life.
	Ended int
}

// CodeFindingsOf is one page of a product's code findings where the subject may read them,
// one row per code finding however many builds it is on.
//
// With no state named it is the queue: open code findings nobody's decision waits on.
// Naming a state lists the code findings in it. A fixed code finding is one closed on a
// build, and listed there until the code finding opens anew at its occurrence on that
// build. Ordered by what is likely real: the rank of the weaknesses the rule
// names, whether another analyzer reports the same flaw, the tool's own
// security severity for the rule, its precision, then newest first.
func CodeFindingsOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope, want State,
	limit, offset int) (*Queue, error) {
	return codeFindingsOf(ctx, db, subject, scope, want, false, limit, offset)
}

// OpenCodeFindingsOf is one page of the code findings a findings file holds: every open code finding
// of the selection, the ones a decision waits on included, as the file's findings
// rows include a finding a decision waits on. A code finding open only in releases past
// their end of life is left out, as the queue leaves it out. Ordered as the
// queue is.
func OpenCodeFindingsOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope,
	limit, offset int) (*Queue, error) {
	return codeFindingsOf(ctx, db, subject, scope, "", true, limit, offset)
}

// codeFindingsOf is CodeFindingsOf, with the open code findings a decision waits on kept in where
// waiting is set and no state is named.
func codeFindingsOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope, want State,
	waiting bool, limit, offset int) (*Queue, error) {

	visible, err := finding.CodeFindingVisible(subject, scope.ProductID)
	if err != nil {
		return nil, err
	}
	perFinding := func() *bun.SelectQuery { return codeFindingFindings(db, subject, scope, visible) }

	// A sighting in a release past its end of life is no work for anybody,
	// so the queue counts none of them, and a code finding open only there leaves
	// the queue though it may still be decided where it is seen elsewhere.
	// The lists by state still show it.
	ended, err := catalog.NewStore(db).BranchesAndTagsPastEndOfLife(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	queued := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where(`"l"."stands" = ?`, string(Open))
		if waiting {
			return q
		}
		return q.Where(`"l"."awaits" = 0`)
	}
	listed := func(q *bun.SelectQuery) *bun.SelectQuery {
		if want != "" {
			return q.Where(`"l"."stands" = ?`, string(want))
		}
		if len(ended) > 0 {
			q = q.Where(`"l"."branch_or_tag_id" NOT IN (?)`, bun.List(ended))
		}
		return queued(q)
	}

	out := &Queue{ByState: map[State]int{}}
	var counted []struct {
		State        State `bun:"stands"`
		Awaits       int   `bun:"awaits"`
		Covered      int   `bun:"covered"`
		CodeFindings int   `bun:"code_findings"`
	}
	if err := db.NewSelect().TableExpr(`(?) AS "l"`, perFinding()).
		ColumnExpr(`"l"."stands", "l"."awaits", "l"."covered", COUNT(DISTINCT "l"."occurrence_identity") AS "code_findings"`).
		GroupExpr(`"l"."stands", "l"."awaits", "l"."covered"`).
		Scan(ctx, &counted); err != nil {
		return nil, fmt.Errorf("count the code findings of product %d: %w", scope.ProductID, err)
	}
	for _, c := range counted {
		out.ByState[c.State] += c.CodeFindings
		if c.State == Open && c.Awaits == 1 {
			out.Waiting += c.CodeFindings
		}
		if c.State == Dismissed && c.Covered == 1 {
			out.Ruled += c.CodeFindings
		}
	}
	if err := listed(db.NewSelect().TableExpr(`(?) AS "l"`, perFinding())).
		ColumnExpr(`COUNT(DISTINCT "l"."occurrence_identity")`).Scan(ctx, &out.Total); err != nil {
		return nil, fmt.Errorf("count the code findings listed in product %d: %w", scope.ProductID, err)
	}
	if want == "" && len(ended) > 0 {
		var all int
		if err := queued(db.NewSelect().TableExpr(`(?) AS "l"`, perFinding())).
			ColumnExpr(`COUNT(DISTINCT "l"."occurrence_identity")`).Scan(ctx, &all); err != nil {
			return nil, fmt.Errorf("count the code findings of product %d past their end of life: %w", scope.ProductID, err)
		}
		out.Ended = all - out.Total
	}

	var page []struct {
		Occurrence string    `bun:"occurrence_identity"`
		Newest     int64     `bun:"newest"`
		Builds     int       `bun:"builds"`
		Opened     time.Time `bun:"opened"`
	}
	if err := listed(db.NewSelect().TableExpr(`(?) AS "l"`, perFinding())).
		ColumnExpr(`"l"."occurrence_identity", MAX("l"."id") AS "newest"`).
		// Builds rather than rows: a code finding fixed, seen again and fixed again
		// on one build is two closed rows there.
		ColumnExpr(`COUNT(DISTINCT "l"."build_id") AS "builds", MIN("l"."opened_at") AS "opened"`).
		GroupExpr(`"l"."occurrence_identity"`).
		OrderExpr(`MAX("l"."tier") DESC, MAX("l"."corroborated") DESC`).
		OrderExpr(`MAX("l"."severity") DESC, MAX("l"."precise") DESC`).
		OrderExpr(`MIN("l"."opened_at") DESC, "l"."occurrence_identity" ASC`).
		Limit(int64(limit)).Offset(int64(offset)).
		Scan(ctx, &page); err != nil {
		return nil, fmt.Errorf("read the code findings of product %d: %w", scope.ProductID, err)
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
		Join(`JOIN "build" AS "t" ON "t"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "t"."branch_or_tag_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		ColumnExpr(`"f"."occurrence_identity", "vu"."identifier" AS "rule"`).
		ColumnExpr(`"ar"."path", "ar"."start_line", "ar"."enclosing", "ar"."message_text"`).
		ColumnExpr(`"s"."name" AS "branch_or_tag", "va"."name" AS "variant", "f"."assigned_to"`).
		// A finding has one sighting, and its last run is the run the evidence
		// reads.
		Join(`JOIN "series_run" AS "sr" ON "sr"."id" = "si"."last_run_id"`).
		ColumnExpr(state+` AS "stands"`, stateArgs...).
		ColumnExpr(`"sr"."third_party"`).
		Where(`"f"."id" IN (?)`, bun.List(newest)).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what the code findings of product %d say: %w", scope.ProductID, err)
	}
	byOccurrence := make(map[string]QueueRow, len(rows))
	for _, r := range rows {
		byOccurrence[r.Occurrence] = r
	}
	out.Rows = make([]QueueRow, 0, len(page))
	for _, p := range page {
		r := byOccurrence[p.Occurrence]
		r.Builds, r.Opened = p.Builds, p.Opened
		r.ThirdParty = declaredIn(r.Declared, r.Path) != ""
		out.Rows = append(out.Rows, r)
	}
	return out, nil
}

// codeFindingFindings is every finding of a code finding in the scope that the subject may
// read, one row per finding: the code finding's occurrence, its build, its series, where it
// stands, whether a decision waits on it, whether a suppression rule covers it, and
// what the queue orders it by.
//
// The product's own visibilities, and a code finding included in its flaw's case. A code finding granted
// one at a time is reached through its evidence, never a list. A finding
// closed on a build is read until the code finding opens anew at its occurrence there.
func codeFindingFindings(db bun.IDB, subject access.Subject, scope Scope, visible []access.Visibility) *bun.SelectQuery {
	reach := finding.CodeFindingReach(subject, scope.ProductID)
	state, stateArgs := stateOf(scope.ProductID)
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	q := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "build" AS "t" ON "t"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "t"."branch_or_tag_id"`).
		Join(`LEFT JOIN "rule_rating" AS "rr" ON "rr"."vulnerability_id" = "f"."vulnerability_id"`).
		ColumnExpr(`"f"."id", "f"."occurrence_identity", "f"."build_id", "f"."opened_at", "si"."series_id", "t"."branch_or_tag_id"`).
		ColumnExpr(`COALESCE("rr"."weakness_tier", 0) AS "tier"`).
		ColumnExpr(`CASE WHEN `+corroborated+` THEN 1 ELSE 0 END AS "corroborated"`).
		ColumnExpr(`COALESCE("rr"."severity_tenths", -1) AS "severity"`).
		ColumnExpr(precisionRank+` AS "precise"`).
		ColumnExpr(state+` AS "stands"`, stateArgs...).
		ColumnExpr(`CASE WHEN `+waitingDecision+` THEN 1 ELSE 0 END AS "awaits"`, scope.ProductID).
		ColumnExpr(`CASE WHEN `+ruled+` THEN 1 ELSE 0 END AS "covered"`, scope.ProductID).
		Where(`"s"."product_id" = ?`, scope.ProductID).
		Where(`("f"."closed_at" IS NULL OR NOT EXISTS (SELECT 1 FROM "finding" AS "fo"
			WHERE "fo"."occurrence_identity" = "f"."occurrence_identity" AND "fo"."build_id" = "f"."build_id"
			  AND "fo"."closed_at" IS NULL))`).
		Where(`("f"."visibility" IN (?) OR `+reach.Included+`)`, append([]any{bun.List(visible)}, reach.IncludedArgs...)...).
		Where(kinds, kindArgs...)
	if scope.BranchOrTagID != nil {
		q = q.Where(`"t"."branch_or_tag_id" = ?`, *scope.BranchOrTagID)
	}
	if scope.VariantID != nil {
		q = q.Where(`"t"."variant_id" = ?`, *scope.VariantID)
	}
	if scope.Unassigned {
		q = q.Where(`"f"."assigned_to" IS NULL`)
	}
	if scope.Method != "" {
		q = q.Where(`"f"."kind" = ?`, methodKinds[scope.Method])
	}
	if scope.Series != "" {
		named, namedArgs := kind.CodeFindings.Where(`"sn"."kind"`)
		q = q.Where(`"si"."series_id" IN (SELECT "sn"."id" FROM "series" AS "sn"
			WHERE "sn"."product_id" = ? AND "sn"."name_folded" = ? AND `+named+`)`,
			append([]any{scope.ProductID, typedname.Matching(scope.Series)}, namedArgs...)...)
	}
	return q
}
