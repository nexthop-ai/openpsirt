// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
)

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

// Scope narrows a product's code findings to one branch or tag, one variant or one build,
// and to one analyzer series. Unset is every one under the product.
type Scope struct {
	ProductID int64
	// Across is the products a list across products reads, each one the
	// reader reads security testing work in, in place of ProductID. A
	// branch, a variant, a build and a subtree belong to one product, so a
	// scope across products names none of them.
	Across        []int64
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
	// Component keeps the code findings placed on one source package: every
	// binary built from a source of this name, or of the source a binary of
	// this name was built from, compared without regard to capitals, in the
	// builds the scope covers, as the component screen reads a name. A name
	// naming a build's root reaches every root the build has had.
	// ComponentVersion keeps the source at one version. Empty, every
	// component.
	Component        string
	ComponentVersion string
	// Beneath keeps the code findings on the build BuildID names that are
	// placed at this component or anywhere under it, by the walk the
	// dependency tree counts with. Under the build's root it is the whole
	// build. Nil, no narrowing.
	Beneath *int64
	BuildID *int64
	// adopted is the components a rescan replaced whose live namesake is
	// beneath Beneath, read once by resolved: a code finding on one is
	// beneath it as well.
	adopted []int64
	// on keeps the code findings on BuildID placed on these components, for
	// counting what sits on each.
	on []int64
	// reached is what Component reaches, read once by resolved and bound as
	// values. Nil where no component is named.
	reached *finding.Reached
}

// resolved is the scope with the names in it read once, as values: what the
// component named reaches in the builds the scope covers, and whether the
// component beneath which it narrows is its build's root, under which it is
// the whole build. Read after the reader is authorized.
func (scope Scope) resolved(ctx context.Context, db bun.IDB) (Scope, error) {
	if name := graph.Folded(strings.TrimSpace(scope.Component)); name != "" && scope.reached == nil {
		builds, err := scope.builds(ctx, db)
		if err != nil {
			return scope, err
		}
		reached, err := finding.ReachedByName(ctx, db, builds, []string{name}, scope.ComponentVersion)
		if err != nil {
			return scope, err
		}
		one := reached[name]
		scope.reached = &one
	}
	if scope.Beneath != nil && scope.BuildID != nil {
		root, err := graph.IsRoot(ctx, db, *scope.BuildID, *scope.Beneath)
		if err != nil {
			return scope, err
		}
		if root {
			scope.Beneath = nil
		} else {
			replaced, err := replacedIn(ctx, db, *scope.BuildID)
			if err != nil {
				return scope, err
			}
			if scope.adopted, err = replacedWithin(ctx, db, *scope.BuildID, *scope.Beneath, replaced); err != nil {
				return scope, err
			}
		}
	}
	return scope, nil
}

// across reports whether the scope reads a list across products.
func (scope Scope) across() bool { return scope.Across != nil }

// bound is what the scope's product-bound conditions compare with.
func (scope Scope) bound() productBound {
	if scope.across() {
		return eachProduct
	}
	return inProduct(scope.ProductID)
}

// inScope keeps a statement over the branch or tag under "s" to the
// scope's product, or its products across.
func (scope Scope) inScope(q *bun.SelectQuery) *bun.SelectQuery {
	where, args := scope.productIn(`"s"."product_id"`)
	return q.Where(where, args...)
}

// productIn is a condition keeping a product column to the scope's product,
// or to its products across. Across no product, it keeps nothing.
func (scope Scope) productIn(column string) (string, []any) {
	if !scope.across() {
		return column + ` = ?`, []any{scope.ProductID}
	}
	if len(scope.Across) == 0 {
		return `1 = 0`, nil
	}
	return column + ` IN (?)`, []any{bun.List(scope.Across)}
}

// mayCount refuses a subject who does not read security testing material in
// the scope's product, or in any one of its products across, before any name
// in the scope is resolved.
func (scope Scope) mayCount(subject access.Subject, what string) error {
	if !scope.across() {
		return MayCount(subject, scope.ProductID, what)
	}
	for _, product := range scope.Across {
		if err := MayCount(subject, product, what); err != nil {
			return err
		}
	}
	return nil
}

// visible is the visibilities the subject reads in the scope's product, which
// readable binds. Across products, readable binds each product's own, so none.
func (scope Scope) visible(subject access.Subject) ([]access.Visibility, error) {
	if scope.across() {
		return nil, nil
	}
	return finding.CodeFindingVisible(subject, scope.ProductID)
}

// readable is the condition keeping the findings under "f" to what the
// subject reads: in one product, the visibilities given and a code finding
// its flaw's case includes; across products, each product's own
// visibilities, bound per product.
func (scope Scope) readable(subject access.Subject, visible []access.Visibility) (string, []any) {
	if scope.across() {
		return access.VisibleWhere(`"s"."product_id"`, `"f"."visibility"`, access.Split(scope.Across, subject.Reads))
	}
	reach := finding.CodeFindingReach(subject, scope.ProductID)
	return `("f"."visibility" IN (?) OR ` + reach.Included + `)`, append([]any{bun.List(visible)}, reach.IncludedArgs...)
}

// builds is every build the scope covers, retired ones included, as the queue
// reads them.
func (scope Scope) builds(ctx context.Context, db bun.IDB) ([]int64, error) {
	if scope.BuildID != nil {
		return []int64{*scope.BuildID}, nil
	}
	q := scope.inScope(db.NewSelect().TableExpr(`"build" AS "t"`).
		Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "t"."branch_or_tag_id"`).
		ColumnExpr(`"t"."id"`))
	if scope.BranchOrTagID != nil {
		q = q.Where(`"t"."branch_or_tag_id" = ?`, *scope.BranchOrTagID)
	}
	if scope.VariantID != nil {
		q = q.Where(`"t"."variant_id" = ?`, *scope.VariantID)
	}
	var out []int64
	if err := q.OrderExpr(`"t"."id"`).Scan(ctx, &out); err != nil {
		return nil, fmt.Errorf("read the builds of product %d: %w", scope.ProductID, err)
	}
	return out, nil
}

// Method is a way of testing our own code, by the word people search for it
// under.
type Method string

// SAST is static analysis: an analyzer reading the source.
const SAST Method = "sast"

// methodKinds is the kind of finding each method records.
var methodKinds = map[Method]kind.Kind{SAST: kind.Analysis}

// Methods is every method the code finding queue narrows by, sorted, which is
// the order a filter offers them. Read from methodKinds, so a method the queue
// cannot narrow by is never offered.
func Methods() []string {
	out := make([]string, 0, len(methodKinds))
	for method := range methodKinds {
		out = append(out, string(method))
	}
	slices.Sort(out)
	return out
}

// CodeFindingAssignees is every word the code finding queue asks who holds a code finding in: the
// findings list's word for work nobody holds.
func CodeFindingAssignees() []string { return []string{finding.HeldByNobody} }

// QueueRow is one code finding in a product: its occurrence, and what the newest of its
// findings in the scope says about it.
type QueueRow struct {
	Occurrence string `bun:"occurrence_identity"`
	// Product is the product the code finding is in, by the name that
	// addresses it, and ProductName the name shown.
	Product     string `bun:"product"`
	ProductName string `bun:"product_name"`
	Rule        string `bun:"rule"`
	Path        string `bun:"path"`
	Line        *int   `bun:"start_line"`
	Function    string `bun:"enclosing"`
	Message     string `bun:"message_text"`
	BranchOrTag string `bun:"branch_or_tag"`
	Variant     string `bun:"variant"`
	// Component is the component the code finding is placed on in that build,
	// Version its version while the build still ships it, and OnBuild says
	// that component is the build itself.
	Component string    `bun:"component"`
	Version   string    `bun:"component_version"`
	OnBuild   bool      `bun:"-"`
	State     State     `bun:"stands"`
	Builds    int       `bun:"builds"`
	Opened    time.Time `bun:"opened"`
	// Placed is OnBuild as the query answers it, 1 or 0, since engines return
	// a boolean expression in different types.
	Placed int `bun:"on_build"`
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
	return codeFindingsOf(ctx, db, subject, scope, want, false, true, limit, offset)
}

// CodeFindingPageOf is the rows of one page of CodeFindingsOf, with none of
// its counts. A file is read a page at a time, and each count covers the
// whole population, so counting on every page costs the file pages times the
// population.
func CodeFindingPageOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope, want State,
	limit, offset int) ([]QueueRow, error) {
	queue, err := codeFindingsOf(ctx, db, subject, scope, want, false, false, limit, offset)
	if err != nil {
		return nil, err
	}
	return queue.Rows, nil
}

// CodeFindingCountsOf is the counts of CodeFindingsOf with no state named,
// and no rows: the queue's length, every state, what waits for a second
// person, what a suppression rule dismisses and what is open only past end of
// life. A security testing figure, so refused to anybody who does not read
// security testing material in the scope's product, or in each product
// across, as the trend is.
func CodeFindingCountsOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope) (*Queue, error) {
	if err := scope.mayCount(subject, "count the code findings"); err != nil {
		return nil, err
	}
	return codeFindingsOf(ctx, db, subject, scope, "", false, true, 0, 0)
}

// OpenCodeFindingsOf is the rows of one page of the code findings a findings
// file holds, with none of the queue's counts: every open code finding of the
// selection, the ones a decision waits on included, as the file's findings
// rows include a finding a decision waits on. A code finding open only in
// releases past their end of life is left out, as the queue leaves it out.
// Ordered as the queue is.
func OpenCodeFindingsOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope,
	limit, offset int) ([]QueueRow, error) {
	queue, err := codeFindingsOf(ctx, db, subject, scope, "", true, false, limit, offset)
	if err != nil {
		return nil, err
	}
	return queue.Rows, nil
}

// codeFindingsOf is CodeFindingsOf, with the open code findings a decision waits on kept in where
// waiting is set and no state is named, and the counts read only where
// counted is set.
func codeFindingsOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope, want State,
	waiting, counted bool, limit, offset int) (*Queue, error) {

	// Across products the scope names only products the reader reads
	// security testing work in, and each row is narrowed to what they read
	// in its own.
	visible, err := scope.visible(subject)
	if err != nil {
		return nil, err
	}
	scope, err = scope.resolved(ctx, db)
	if err != nil {
		return nil, err
	}
	// Whether another analyzer agrees is read for the page alone, the one
	// statement ordering by it.
	perFinding := func(keep State, ordered bool) *bun.SelectQuery {
		q := codeFindingFindings(db, subject, scope, visible, keep)
		if ordered {
			q = q.ColumnExpr(`CASE WHEN "f"."id" IN (?) THEN 1 ELSE 0 END AS "corroborated"`, scope.corroboratedIn(db, keep == Fixed))
		}
		return q
	}

	// A sighting in a release past its end of life is no work for anybody,
	// so the queue counts none of them, and a code finding open only there leaves
	// the queue though it may still be decided where it is seen elsewhere.
	// The lists by state still show it.
	ended, err := catalog.NewStore(db).BranchesAndTagsPastEndOfLife(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	queued := func(ordered bool) *bun.SelectQuery {
		q := perFinding(Open, ordered)
		if !waiting {
			q = q.Apply(scope.notWaiting(db))
		}
		return db.NewSelect().TableExpr(`(?) AS "l"`, q)
	}
	listed := func(ordered bool) *bun.SelectQuery {
		if want != "" {
			return db.NewSelect().TableExpr(`(?) AS "l"`, perFinding(want, ordered))
		}
		q := queued(ordered)
		if len(ended) > 0 {
			q = q.Where(`"l"."branch_or_tag_id" NOT IN (?)`, bun.List(ended))
		}
		return q
	}

	out := &Queue{ByState: map[State]int{}}
	if counted {
		var byState []struct {
			State        State `bun:"stands"`
			Awaits       int   `bun:"awaits"`
			Covered      int   `bun:"covered"`
			CodeFindings int   `bun:"code_findings"`
		}
		if err := db.NewSelect().TableExpr(`(?) AS "l"`, perFinding("", false).Apply(scope.stood(db))).
			ColumnExpr(`"l"."stands", "l"."awaits", "l"."covered", COUNT(DISTINCT "l"."occurrence_identity") AS "code_findings"`).
			GroupExpr(`"l"."stands", "l"."awaits", "l"."covered"`).
			Scan(ctx, &byState); err != nil {
			return nil, fmt.Errorf("count the code findings of product %d: %w", scope.ProductID, err)
		}
		for _, c := range byState {
			out.ByState[c.State] += c.CodeFindings
			if c.State == Open && c.Awaits == 1 {
				out.Waiting += c.CodeFindings
			}
			if c.State == Dismissed && c.Covered == 1 {
				out.Ruled += c.CodeFindings
			}
		}
		if err := listed(false).
			ColumnExpr(`COUNT(DISTINCT "l"."occurrence_identity")`).Scan(ctx, &out.Total); err != nil {
			return nil, fmt.Errorf("count the code findings listed in product %d: %w", scope.ProductID, err)
		}
		if want == "" && len(ended) > 0 {
			var all int
			if err := queued(false).
				ColumnExpr(`COUNT(DISTINCT "l"."occurrence_identity")`).Scan(ctx, &all); err != nil {
				return nil, fmt.Errorf("count the code findings of product %d past their end of life: %w", scope.ProductID, err)
			}
			out.Ended = all - out.Total
		}
	}

	// Counts alone: no page is read.
	if limit <= 0 {
		return out, nil
	}
	var page []struct {
		Occurrence string    `bun:"occurrence_identity"`
		Newest     int64     `bun:"newest"`
		Builds     int       `bun:"builds"`
		Opened     time.Time `bun:"opened"`
	}
	if err := listed(true).
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
	state, stateArgs := stateAt(scope.bound())
	var rows []QueueRow
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "build" AS "t" ON "t"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "t"."branch_or_tag_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "s"."product_id"`).
		ColumnExpr(`"p"."name" AS "product", `+catalog.ShownExpr("p")+` AS "product_name"`).
		ColumnExpr(`"f"."occurrence_identity", "vu"."identifier" AS "rule"`).
		ColumnExpr(`"ar"."path", "ar"."start_line", "ar"."enclosing", "ar"."message_text"`).
		ColumnExpr(`"s"."name" AS "branch_or_tag", "va"."name" AS "variant", "f"."assigned_to"`).
		Join(`JOIN "component" AS "co" ON "co"."id" = "f"."component_id"`).
		ColumnExpr(placedOn, true).
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
		r.Builds, r.Opened, r.OnBuild = p.Builds, p.Opened, r.Placed == 1
		r.ThirdParty = declaredIn(r.Declared, r.Path) != ""
		out.Rows = append(out.Rows, r)
	}
	return out, nil
}

// codeFindingFindings is every finding of a code finding in the scope that the subject may
// read, one row per finding: the code finding's occurrence, its build, its series, and
// what the queue orders it by, except whether another analyzer agrees, which the page
// adds. Where it stands is added by stood, for the reads that count by it. Where keep
// names a state, only the findings standing in it, kept by the conditions that make
// it (inState).
//
// The product's own visibilities, and a code finding included in its flaw's case. A code finding granted
// one at a time is reached through its evidence, never a list. A finding
// closed on a build is read until the code finding opens anew at its occurrence there,
// which a state other than fixed has no need to ask.
//
// Across products, the rows are each product's the reader reads security
// testing work in, at the visibilities they read in it.
func codeFindingFindings(db bun.IDB, subject access.Subject, scope Scope, visible []access.Visibility,
	keep State) *bun.SelectQuery {
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	q := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "build" AS "t" ON "t"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "t"."branch_or_tag_id"`).
		Join(`LEFT JOIN "rule_rating" AS "rr" ON "rr"."vulnerability_id" = "f"."vulnerability_id"`).
		ColumnExpr(`"f"."id", "f"."occurrence_identity", "f"."build_id", "f"."component_id", "f"."opened_at", "si"."series_id", "t"."branch_or_tag_id"`).
		ColumnExpr(`COALESCE("rr"."weakness_tier", 0) AS "tier"`).
		ColumnExpr(`COALESCE("rr"."severity_tenths", -1) AS "severity"`).
		ColumnExpr(precisionRank+` AS "precise"`).
		Where(kinds, kindArgs...)
	if keep == "" || keep == Fixed {
		// A closed finding is read until its code finding opens anew on its
		// build.
		q = q.Where(`("f"."closed_at" IS NULL
			OR "f"."id" NOT IN (?))`, scope.reopenedIn(db))
	}
	if keep != "" {
		q = q.Apply(scope.inState(db, keep))
	}
	where, args := scope.readable(subject, visible)
	return scope.narrow(db, scope.inScope(q.Where(where, args...)), kind.CodeFindings)
}

// stood adds to a statement over the finding under "f", whose sighting is
// under "si" and whose result is under "ar", where it stands in the scope,
// whether a decision waits on it while it is open and whether a suppression
// rule covers it. Added only where a read counts by them, because MySQL 8.4
// works out every column of a derived table it materializes, read or not:
// 0.16 s of the queue's 0.36 s count over 36,000 open code findings.
//
// Whether a decision stands or waits is asked of each row by identifier from
// decidedIn's sets, and the standing outcome read only where one stands.
// Asked of each row, MySQL 8.4 read every decision of the product for each
// code finding, through the index the product leads: 0.22 s against 0.13 s
// for home's counts across two products, analyzed.
func (scope Scope) stood(db bun.IDB) func(*bun.SelectQuery) *bun.SelectQuery {
	return func(q *bun.SelectQuery) *bun.SelectQuery {
		bound := scope.bound()
		state, stateArgs := stateDecidedBy(bound, `"f"."id" IN (?)`, []any{scope.decidedIn(db, standing)})
		return q.ColumnExpr(state+` AS "stands"`, stateArgs...).
			ColumnExpr(`CASE WHEN "f"."id" IN (?) THEN 1 ELSE 0 END AS "awaits"`, scope.decidedIn(db, waiting)).
			ColumnExpr(`CASE WHEN `+ruledIn(bound)+` THEN 1 ELSE 0 END AS "covered"`, bound.times(1)...)
	}
}

// reopenedIn is the closed code findings of the scope's builds at whose
// occurrence a code finding is open again on the same build.
//
// The code findings of those builds are read once, and each is told whether
// one of its occurrence on its build is open as a window over the two; the
// closed ones so told are asked of each row by identifier. A window, because
// asked of each closed finding MySQL 8.4 took past 30 s for one count with
// statistics as loaded, and every other pairing was planned by some engine
// through every open finding of the build
// (design-docs/analysis-measurements.md § Code finding queue).
//
// Code findings alone: an occurrence a code finding is at is named from its
// series and key, which no other kind of finding is at.
func (scope Scope) reopenedIn(db bun.IDB) *bun.SelectQuery {
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	told := scope.builtIn(db.NewSelect().TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."id", "f"."closed_at"`).
		ColumnExpr(`MAX(CASE WHEN "f"."closed_at" IS NULL THEN 1 ELSE 0 END)
			OVER (PARTITION BY "f"."occurrence_identity", "f"."build_id") AS "open_there"`).
		Where(kinds, kindArgs...))
	return identifiers(db, db.NewSelect().TableExpr(`(?) AS "ro"`, told).
		ColumnExpr(`"ro"."id"`).
		Where(`"ro"."closed_at" IS NOT NULL AND "ro"."open_there" = 1`).
		GroupExpr(`"ro"."id"`))
}

// identifiers is a set of identifiers, read under "id" and grouped by it, as
// a set an engine looks each row up in. Asked of each row as a statement of
// its own, MariaDB 11.4 compared every row with all of the set and took past
// 30 s for 8,000 code findings; a grouped set it reads once and keys by what
// it is grouped by, and an engine drops a grouping written in the statement
// asked.
func identifiers(db bun.IDB, set *bun.SelectQuery) *bun.SelectQuery {
	return db.NewSelect().TableExpr(`(?) AS "ks"`, set).ColumnExpr(`"ks"."id"`)
}

// builtIn keeps a statement over the findings under "f" to the builds the
// scope covers: its products, branch or tag, variant and build. The rest of
// the scope narrows which code findings are listed, never which of their
// builds' code findings they are compared with.
func (scope Scope) builtIn(q *bun.SelectQuery) *bun.SelectQuery {
	q = q.Join(`JOIN "build" AS "t" ON "t"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "t"."branch_or_tag_id"`)
	if scope.BranchOrTagID != nil {
		q = q.Where(`"t"."branch_or_tag_id" = ?`, *scope.BranchOrTagID)
	}
	if scope.VariantID != nil {
		q = q.Where(`"t"."variant_id" = ?`, *scope.VariantID)
	}
	if scope.BuildID != nil {
		q = q.Where(`"f"."build_id" = ?`, *scope.BuildID)
	}
	return scope.inScope(q)
}

// narrow keeps a statement over the findings under "f", their sightings under
// "si" and their builds under "t" to the scope's branch or tag, variant,
// holder, method, component, build, subtree and series, after inScope has kept
// it to the scope's products. reader is the consumer the statement reads for,
// whose kinds the series it names are of.
func (scope Scope) narrow(db bun.IDB, q *bun.SelectQuery, reader kind.Consumer) *bun.SelectQuery {
	bound := scope.bound()
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
	if scope.reached != nil {
		// The folds the name reaches, as values: a binary's name reaches
		// every binary of its source.
		if len(scope.reached.Folds) == 0 {
			q = q.Where("1 = 0")
		} else {
			q = q.Join(`JOIN "component" AS "pc" ON "pc"."id" = "f"."component_id"`).
				Where(`"pc"."fold_key" IN (?)`, bun.List(scope.reached.Folds))
		}
	}
	if scope.BuildID != nil {
		q = q.Where(`"f"."build_id" = ?`, *scope.BuildID)
		if scope.Beneath != nil {
			// The subtree as the engine walks it. Under the build's root it
			// is the whole build, which resolved has made no narrowing.
			cond, args := beneathOrAdopted(db, *scope.BuildID, *scope.Beneath, scope.adopted)
			q = q.Where(cond, args...)
		}
		if scope.on != nil {
			q = q.Where(`"f"."component_id" IN (?)`, bun.List(scope.on))
		}
	}
	if scope.Series != "" {
		named, namedArgs := reader.Where(`"sn"."kind"`)
		q = q.Where(`"si"."series_id" IN (SELECT "sn"."id" FROM "series" AS "sn"
			WHERE "sn"."product_id" = `+bound.sql+` AND "sn"."name_folded" = ? AND `+named+`)`,
			append(append(bound.times(1), typedname.Matching(scope.Series)), namedArgs...)...)
	}
	return q
}
