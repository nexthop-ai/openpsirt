// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Answered is what people said of the code findings of one series, or of one
// analyzer rule in a series, counted by occurrence: each code finding is in
// one count alone.
type Answered struct {
	Series string
	// Rule is the analyzer rule, empty on a series' own row.
	Rule string
	// Dismissed, NotSecurity and Confirmed are the code findings whose
	// standing decision says so; Confirmed takes those recorded as a flaw.
	Dismissed   int
	NotSecurity int
	Confirmed   int
	// Ruled is the code findings a suppression rule dismisses, with no
	// decision standing.
	Ruled int
	// Fixed is the code findings a person closed as fixed with no decision
	// standing: a fix says the code finding was real.
	Fixed int
	// Unjudged is the code findings nothing answers yet, a decision waiting
	// for a second person included.
	Unjudged int
}

// Judged is how many code findings a person or a suppression rule answered.
func (a Answered) Judged() int {
	return a.Dismissed + a.NotSecurity + a.Ruled + a.Confirmed + a.Fixed
}

// Noise is how many of those judged were answered as noise: dismissed, not a
// security issue, or dismissed by a suppression rule.
func (a Answered) Noise() int { return a.Dismissed + a.NotSecurity + a.Ruled }

// Precision is which analyzers and rules are noise: what was said of the code
// findings of each series and each rule, and the product's suppression rules
// with what each covers.
type Precision struct {
	BySeries []Answered
	// ByRule is every analyzer rule with a code finding judged, the noisiest
	// share first.
	ByRule []Answered
	// Rules are the product's suppression rules, retired ones included, as
	// the rules list reads them.
	Rules []SuppressionRule
}

// PrecisionOf is what was said of the code findings in the scope, by series
// and by analyzer rule, and the product's suppression rules.
//
// A code finding is counted once, by its occurrence, at the first of these
// that holds: the decision standing at it; a flaw record; a closure as fixed
// on a build with no finding of it open there since; a suppression rule
// covering it; and otherwise unjudged. A decision is the occurrence's in the
// product, so every build holding it reads the same one.
//
// Refused to anybody who does not read security testing material in the
// product, before any name in the scope is resolved.
func PrecisionOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope) (*Precision, error) {
	if err := MayCount(subject, scope.ProductID, "measure the precision of the analyzers"); err != nil {
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
	var rows []struct {
		Occurrence string  `bun:"occurrence_identity"`
		SeriesID   int64   `bun:"series_id"`
		Rule       string  `bun:"rule"`
		Closed     int     `bun:"closed"`
		Outcome    *string `bun:"outcome"`
		Flaw       int     `bun:"flaw"`
		Covered    int     `bun:"covered"`
	}
	if err := statisticsFindings(db, subject, scope, visible).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "f"."vulnerability_id"`).
		ColumnExpr(`"f"."occurrence_identity", "si"."series_id", "vu"."identifier" AS "rule"`).
		ColumnExpr(`CASE WHEN "f"."closed_at" IS NULL THEN 0 ELSE 1 END AS "closed"`).
		ColumnExpr(standingOutcomeIn(product)+` AS "outcome"`, product.times(1)...).
		ColumnExpr(`CASE WHEN `+recordedAsFlawIn(product)+` THEN 1 ELSE 0 END AS "flaw"`, product.times(1)...).
		ColumnExpr(`CASE WHEN `+ruledIn(product)+` THEN 1 ELSE 0 END AS "covered"`, product.times(1)...).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what was said of the code findings of product %d: %w", scope.ProductID, err)
	}
	names, err := seriesNames(ctx, db, scope.ProductID)
	if err != nil {
		return nil, err
	}

	type occurrence struct {
		series, rule        string
		outcome             *string
		flaw, covered, open bool
		closed              bool
	}
	// A finding closed on a build and opened anew there is read beside the
	// open one, as the queue does not: the open one makes the occurrence
	// open, and both carry its occurrence's path, so the counts agree.
	// Asked of each closed finding in the statement, MySQL reads every open
	// finding of its build (design-docs/analysis-measurements.md § Security
	// testing figures).
	at := map[string]*occurrence{}
	for _, row := range rows {
		one := at[row.Occurrence]
		if one == nil {
			one = &occurrence{series: names[row.SeriesID], rule: row.Rule, outcome: row.Outcome}
			at[row.Occurrence] = one
		}
		one.flaw = one.flaw || row.Flaw == 1
		one.covered = one.covered || row.Covered == 1
		if row.Closed == 1 {
			one.closed = true
		} else {
			one.open = true
		}
	}
	bySeries, byRule := map[string]*Answered{}, map[[2]string]*Answered{}
	for _, one := range at {
		series := bySeries[one.series]
		if series == nil {
			series = &Answered{Series: one.series}
			bySeries[one.series] = series
		}
		rule := byRule[[2]string{one.series, one.rule}]
		if rule == nil {
			rule = &Answered{Series: one.series, Rule: one.rule}
			byRule[[2]string{one.series, one.rule}] = rule
		}
		for _, counted := range []*Answered{series, rule} {
			switch {
			case one.outcome != nil && *one.outcome == string(Dismissed):
				counted.Dismissed++
			case one.outcome != nil && *one.outcome == string(NotSecurity):
				counted.NotSecurity++
			case one.outcome != nil || one.flaw:
				counted.Confirmed++
			case one.closed && !one.open:
				counted.Fixed++
			case one.covered:
				counted.Ruled++
			default:
				counted.Unjudged++
			}
		}
	}
	out := &Precision{BySeries: []Answered{}, ByRule: []Answered{}}
	for _, each := range bySeries {
		out.BySeries = append(out.BySeries, *each)
	}
	sort.Slice(out.BySeries, func(i, j int) bool { return out.BySeries[i].Series < out.BySeries[j].Series })
	for _, each := range byRule {
		if each.Judged() > 0 {
			out.ByRule = append(out.ByRule, *each)
		}
	}
	sort.Slice(out.ByRule, func(i, j int) bool {
		a, b := out.ByRule[i], out.ByRule[j]
		// The noisiest share first, compared without division.
		if left, right := a.Noise()*b.Judged(), b.Noise()*a.Judged(); left != right {
			return left > right
		}
		if a.Judged() != b.Judged() {
			return a.Judged() > b.Judged()
		}
		if a.Series != b.Series {
			return a.Series < b.Series
		}
		return a.Rule < b.Rule
	})
	if out.Rules, err = SuppressionRules(ctx, db, subject, scope.ProductID); err != nil {
		return nil, err
	}
	return out, nil
}
