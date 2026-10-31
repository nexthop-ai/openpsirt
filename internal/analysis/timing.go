// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// Waits is how long a set of code findings waited: the whole set, and the set
// split by the tier of each rule's weaknesses as rated now, every tier named.
type Waits struct {
	All    triage.Spread
	ByTier map[string]triage.Spread
}

// waitsOf is the waits of each code finding, by tier.
func waitsOf(byTier map[string][]time.Duration) Waits {
	out := Waits{ByTier: map[string]triage.Spread{}}
	var all []time.Duration
	for _, tier := range weakness.Tiers() {
		waited := byTier[tier.Name()]
		all = append(all, waited...)
		out.ByTier[tier.Name()] = triage.SpreadOf(tier.Name(), waited)
	}
	out.All = triage.SpreadOf("", all)
	return out
}

// Aged is the code findings waiting for a person whose age falls in one
// stretch of days before now, by tier.
type Aged struct {
	Stretch finding.Stretch
	Waiting int
	ByTier  map[string]int
}

// Judging is how long code findings wait for a person: the wait from a code
// finding opening to the first decision proposed about it, over the first
// decisions proposed in a window; the code findings waiting now, by age; and
// those no longer detected now, which wait on nobody.
type Judging struct {
	Judged  Waits
	Waiting []Aged
	// Oldest is when the longest-waiting code finding opened, nil where none
	// waits.
	Oldest *time.Time
	// NoLongerDetected is the queue's count of that state now, shown apart:
	// a run stopped seeing them, so they are in no queue and wait on nobody.
	NoLongerDetected int
}

// TimeToJudge is how long code findings in the scope wait for a person.
//
// A wait runs from a code finding opening, its earliest opening on any build
// in the scope, to the first decision anybody proposed about it at its
// occurrence, whatever its outcome and whether or not it stands now. It is
// counted where that first proposal falls in [since, until). A dismissal is a
// judgment and counts; a code finding a suppression rule covers was judged by
// no person and has no wait.
//
// Waiting is the queue: open code findings nobody's decision waits on, by the
// age of their earliest opening now, in the stretches the vulnerability
// backlog ages in. A code finding open only in releases past their end of
// life is left out, as the queue leaves it out. Refused to anybody who does
// not read security testing material in the product, before any name in the
// scope is resolved. Across products, every product of the scope is one the
// reader reads security testing material in, each counted at its own
// visibilities and against its own decisions.
func TimeToJudge(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope,
	since, until, now time.Time) (*Judging, error) {

	if err := scope.mayCount(subject, "time the judging of code findings"); err != nil {
		return nil, err
	}
	visible, err := scope.visible(subject)
	if err != nil {
		return nil, err
	}
	if scope, err = scope.resolved(ctx, db); err != nil {
		return nil, err
	}

	// The first proposal at each occurrence in the product, kept where it
	// falls in the window: the decisions joined to the findings and grouped,
	// never asked per finding. Asked per finding as a correlated test,
	// PostgreSQL reads every finding of the product before asking which hold
	// a decision: 7.96 s against 195 ms for 4,000 code findings
	// (design-docs/analysis-measurements.md § Security testing figures).
	var judged []struct {
		Occurrence string    `bun:"occurrence_identity"`
		Tier       int       `bun:"tier"`
		OpenedAt   time.Time `bun:"opened_at"`
		First      time.Time `bun:"first_proposed"`
	}
	// Subtraction is spelled four ways across the engines, so the waits are
	// worked out here. A decision is one product's, so across products each
	// finding reads its own product's.
	bound := scope.bound()
	if err := statisticsFindings(db, subject, scope, visible).
		Join(`JOIN "decision_occurrence" AS "de" ON "de"."product_id" = `+bound.sql, bound.times(1)...).
		Join(`JOIN "vulnerability" AS "dv" ON "dv"."id" = "de"."vulnerability_id"`).
		Where(finding.DecisionOccurrenceOf("f")).
		ColumnExpr(`"f"."occurrence_identity", COALESCE("rr"."weakness_tier", 0) AS "tier", "f"."opened_at"`).
		ColumnExpr(`MIN("de"."proposed_at") AS "first_proposed"`).
		GroupExpr(`"f"."id", "f"."occurrence_identity", "rr"."weakness_tier", "f"."opened_at"`).
		Having(`MIN("de"."proposed_at") >= ?`, since).
		Having(`MIN("de"."proposed_at") < ?`, until).
		Scan(ctx, &judged); err != nil {
		return nil, fmt.Errorf("read when the code findings of product %d were first judged: %w", scope.ProductID, err)
	}
	type wait struct {
		tier          int
		opened, first time.Time
	}
	byOccurrence := map[string]*wait{}
	for _, row := range judged {
		one := byOccurrence[row.Occurrence]
		if one == nil {
			byOccurrence[row.Occurrence] = &wait{tier: row.Tier, opened: row.OpenedAt, first: row.First}
			continue
		}
		if row.OpenedAt.Before(one.opened) {
			one.opened = row.OpenedAt
		}
	}
	waited := map[string][]time.Duration{}
	for _, one := range byOccurrence {
		// A decision outlives a closure, so a code finding opened anew may
		// have been judged before its opening here: it waited for nobody.
		name := weakness.Tier(one.tier).Name()
		waited[name] = append(waited[name], max(one.first.Sub(one.opened), 0))
	}
	out := &Judging{Judged: waitsOf(waited)}

	// The queue's own rows, so the stretches add up to the list they open.
	ended, err := catalog.NewStore(db).BranchesAndTagsPastEndOfLife(ctx, now)
	if err != nil {
		return nil, err
	}
	queued := db.NewSelect().TableExpr(`(?) AS "l"`,
		codeFindingFindings(db, subject, scope, visible, Open).Apply(notWaiting(scope.bound()))).
		ColumnExpr(`MIN("l"."opened_at") AS "opened", MAX("l"."tier") AS "tier"`).
		GroupExpr(`"l"."occurrence_identity"`)
	if len(ended) > 0 {
		queued = queued.Where(`"l"."branch_or_tag_id" NOT IN (?)`, bun.List(ended))
	}
	var waiting []struct {
		Opened time.Time `bun:"opened"`
		Tier   int       `bun:"tier"`
	}
	if err := queued.Scan(ctx, &waiting); err != nil {
		return nil, fmt.Errorf("read the code findings of product %d waiting for a person: %w", scope.ProductID, err)
	}
	for _, stretch := range finding.AgingStretches() {
		aged := Aged{Stretch: stretch, ByTier: map[string]int{}}
		for _, tier := range weakness.Tiers() {
			aged.ByTier[tier.Name()] = 0
		}
		out.Waiting = append(out.Waiting, aged)
	}
	for _, row := range waiting {
		days := int(now.Sub(row.Opened) / (24 * time.Hour))
		for i, aged := range out.Waiting {
			if days >= aged.Stretch.From && (aged.Stretch.To == 0 || days < aged.Stretch.To) {
				out.Waiting[i].Waiting++
				out.Waiting[i].ByTier[weakness.Tier(row.Tier).Name()]++
				break
			}
		}
		if out.Oldest == nil || row.Opened.Before(*out.Oldest) {
			opened := row.Opened
			out.Oldest = &opened
		}
	}
	if out.NoLongerDetected, err = noLongerDetected(ctx, db, subject, scope, visible); err != nil {
		return nil, err
	}
	return out, nil
}

// Fixing is how long code findings take to be fixed: the wait from a code
// finding opening to a person closing it as fixed, over the fixes in a
// window, and apart from it the code findings no longer detected now, timed
// from opening to the run that stopped seeing them.
type Fixing struct {
	Fixed Waits
	// Dismissed is the code findings fixed in the window and left out,
	// because a dismissal or a suppression rule answers them.
	Dismissed int
	// NoLongerDetected is timed to the run that first did not see each one:
	// absence, which is no proof of a fix. Today's alone, since a return
	// clears an absence.
	NoLongerDetected Waits
}

// TimeToFix is how long code findings in the scope take to be fixed.
//
// A code finding is fixed when a person has closed it as fixed on every build
// in the scope holding it, as the trend takes it off the line, and timed from
// its earliest opening to its last closing. It is counted where that closing
// falls in [since, until). Dismissals are left out: a code finding whose
// standing decision dismisses it, or says it is not a security issue, or that
// a suppression rule covers with no decision standing, is counted in
// Dismissed alone. Absence closes nothing, so a code finding no longer
// detected is timed apart, to the run that stopped seeing it.
//
// Refused to anybody who does not read security testing material in the
// product, before any name in the scope is resolved.
func TimeToFix(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope,
	since, until time.Time) (*Fixing, error) {

	if err := MayCount(subject, scope.ProductID, "time the fixing of code findings"); err != nil {
		return nil, err
	}
	visible, err := finding.CodeFindingVisible(subject, scope.ProductID)
	if err != nil {
		return nil, err
	}
	if scope, err = scope.resolved(ctx, db); err != nil {
		return nil, err
	}
	product := inProduct(scope.ProductID)
	state, stateArgs := stateAt(product)
	var rows []struct {
		Occurrence string     `bun:"occurrence_identity"`
		Tier       int        `bun:"tier"`
		OpenedAt   time.Time  `bun:"opened_at"`
		ClosedAt   *time.Time `bun:"closed_at"`
		Stands     State      `bun:"stands"`
		Outcome    *string    `bun:"outcome"`
		Covered    int        `bun:"covered"`
		AbsentAt   *time.Time `bun:"absent_at"`
	}
	// Every finding still open, for what is no longer detected and for what
	// keeps an occurrence from being fixed, and every finding of an
	// occurrence closed in the window, for its earliest opening. The closings
	// are the product's code findings alone: with every closing in the
	// deployment under the OR, PostgreSQL took 5.9 s at 240,957 dependency
	// closings (design-docs/analysis-measurements.md § Security testing
	// figures).
	closedKinds, closedKindArgs := kind.SecurityTestingStatistics.Where(`"fx"."kind"`)
	closedIn := db.NewSelect().TableExpr(`"finding" AS "fx"`).
		Join(`JOIN "build" AS "xt" ON "xt"."id" = "fx"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "xs" ON "xs"."id" = "xt"."branch_or_tag_id"`).
		ColumnExpr(`"fx"."occurrence_identity"`).
		Where(`"xs"."product_id" = ?`, scope.ProductID).
		Where(closedKinds, closedKindArgs...).
		Where(`"fx"."closed_at" >= ?`, since).Where(`"fx"."closed_at" < ?`, until)
	if err := statisticsFindings(db, subject, scope, visible).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`LEFT JOIN "series_run" AS "ab" ON "ab"."id" = "si"."absent_run_id"`).
		ColumnExpr(`"f"."occurrence_identity", COALESCE("rr"."weakness_tier", 0) AS "tier"`).
		ColumnExpr(`"f"."opened_at", "f"."closed_at", "ab"."applied_at" AS "absent_at"`).
		ColumnExpr(state+` AS "stands"`, stateArgs...).
		ColumnExpr(standingOutcomeIn(product)+` AS "outcome"`, product.times(1)...).
		ColumnExpr(`CASE WHEN `+ruledIn(product)+` THEN 1 ELSE 0 END AS "covered"`, product.times(1)...).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr(`"f"."closed_at" IS NULL`).WhereOr(`"f"."occurrence_identity" IN (?)`, closedIn)
		}).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read when the code findings of product %d were fixed: %w", scope.ProductID, err)
	}

	type occurrence struct {
		tier             int
		opened           time.Time
		open, dismissed  bool
		lastClosed       *time.Time
		absent, absentAt bool
		firstAbsent      time.Time
	}
	at := map[string]*occurrence{}
	for _, row := range rows {
		one := at[row.Occurrence]
		if one == nil {
			one = &occurrence{tier: row.Tier, opened: row.OpenedAt}
			at[row.Occurrence] = one
		}
		if row.OpenedAt.Before(one.opened) {
			one.opened = row.OpenedAt
		}
		// A decision is about the occurrence, so every finding of it reads
		// the same one.
		if row.Outcome != nil {
			one.dismissed = *row.Outcome == string(Dismissed) || *row.Outcome == string(NotSecurity)
		} else if row.Covered == 1 {
			one.dismissed = true
		}
		if row.ClosedAt == nil {
			one.open = true
		} else if one.lastClosed == nil || row.ClosedAt.After(*one.lastClosed) {
			one.lastClosed = row.ClosedAt
		}
		if row.Stands == NoLongerDetected {
			one.absent = true
			if row.AbsentAt != nil && (!one.absentAt || row.AbsentAt.Before(one.firstAbsent)) {
				one.absentAt, one.firstAbsent = true, *row.AbsentAt
			}
		}
	}
	out := &Fixing{}
	fixed, absent := map[string][]time.Duration{}, map[string][]time.Duration{}
	for _, one := range at {
		name := weakness.Tier(one.tier).Name()
		if one.absent && one.absentAt {
			absent[name] = append(absent[name], max(one.firstAbsent.Sub(one.opened), 0))
		}
		if one.open || one.lastClosed == nil || one.lastClosed.Before(since) || !one.lastClosed.Before(until) {
			continue
		}
		if one.dismissed {
			out.Dismissed++
			continue
		}
		fixed[name] = append(fixed[name], one.lastClosed.Sub(one.opened))
	}
	out.Fixed, out.NoLongerDetected = waitsOf(fixed), waitsOf(absent)
	return out, nil
}

// noLongerDetected is the queue's count of code findings no longer detected in
// the scope, now, so a figure is the length of the list it opens.
func noLongerDetected(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope,
	visible []access.Visibility) (int, error) {
	var out int
	if err := db.NewSelect().
		TableExpr(`(?) AS "l"`, codeFindingFindings(db, subject, scope, visible, NoLongerDetected)).
		ColumnExpr(`COUNT(DISTINCT "l"."occurrence_identity")`).
		Scan(ctx, &out); err != nil {
		return 0, fmt.Errorf("count the code findings of product %d no longer detected: %w", scope.ProductID, err)
	}
	return out, nil
}
