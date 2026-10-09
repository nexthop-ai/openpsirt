// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"github.com/uptrace/bun"
)

// The findings list's groups in two levels.
//
// A group is one issue at one fold, and the fold is a text key on the
// component. Grouping a build's open rows on it directly sorts every row on a
// 64-character string: on 367,000 open rows that sort spills to disk, and it is
// most of the time the list takes. So the places are grouped first on two
// integers — the issue and the component — and only those partial groups are
// joined to the component and grouped again on the fold. A fold is a handful
// of components at most, so the second grouping sorts thousands of rows rather
// than hundreds of thousands. DESIGN-findings.md § Two-level grouping holds the
// measurement.
//
// Every aggregate a group reports or is filtered on decomposes exactly. A
// count is the sum of the partial counts, a minimum the minimum of the partial
// minimums, a maximum likewise, and a count of distinct components or issues is
// a count of the partial groups that carry them. A count of distinct builds is
// the one that does not, and where a filter asks it the build is a third key of
// the first level.
//
// The partial columns are named apart from what the second level reports, so
// that an ORDER BY naming a reported column cannot be read as naming one of
// these. Where a partial carries the same aggregate under the column's own
// name — the earliest opening, the soonest deadline — the condition and the
// order that read it are spelled the same at both levels.

// grain is which level a condition over a group is spelled at: over the
// places themselves, or over the partial groups of the two-level form.
type grain bool

const (
	// overRows asks a group's aggregates of its places.
	overRows grain = false
	// overParts asks them of the partial groups, read under the alias "f".
	overParts grain = true
)

// places is how many places the group holds.
func (g grain) places() string { return g.pick("COUNT(*)", "SUM(f.n)") }

// peak is the highest urgency among the group's places.
func (g grain) peak() string { return g.pick("MAX(f.urgency)", "MAX(f.peak)") }

// exploited and exploitedHere are the two exploitation flags.
func (g grain) exploited() string { return g.pick(exploitedAcross, "MAX(f.hit)") }

func (g grain) exploitedHere() string { return g.pick(exploitedHereAcross, "MAX(f.hit_here)") }

// withFix is how many places name a version that fixes the issue.
func (g grain) withFix() string { return g.pick(withFixAcross, "SUM(f.with_fix)") }

// fixLeast and fixMost are the two ends of what upstream did.
func (g grain) fixLeast() string { return g.pick("MIN(f.fix_state)", "MIN(f.fix_least)") }

func (g grain) fixMost() string { return g.pick("MAX(f.fix_state)", "MAX(f.fix_most)") }

// held is how many places somebody holds, and heldLeast and heldMost the two
// ends of who.
func (g grain) held() string { return g.pick("COUNT(f.assigned_to)", "SUM(f.held)") }

func (g grain) heldLeast() string { return g.pick("MIN(f.assigned_to)", "MIN(f.held_least)") }

func (g grain) heldMost() string { return g.pick("MAX(f.assigned_to)", "MAX(f.held_most)") }

// decided is how many places carry one of the flags byState's derived table
// computes per place.
func (g grain) decided(flag string) string {
	switch flag {
	case "waiting", "approved", "lapsed", "planned", "this_outcome":
	default:
		panic("finding: " + flag + " is not a column of the decided table")
	}
	return g.pick("SUM(COALESCE(dd."+flag+", 0))", `SUM(f.`+flag+`)`)
}

func (g grain) pick(rows, parts string) string {
	if g == overParts {
		return parts
	}
	return rows
}

// withFixAcross counts the places naming a fixed version.
const withFixAcross = "SUM(CASE WHEN f.fixed_in IS NULL OR f.fixed_in = '' THEN 0 ELSE 1 END)"

// folded is the first level of the two-level form joined to the component, as
// a query a caller groups on the fold and selects from.
//
// rows is the population: open findings of the selection, read as "f", with
// whatever joins the caller's own conditions need. keyed adds the first
// level's grouping keys and selects them; the issue and the component are
// always among them. Everything the filter asks of a place is applied to the
// first level and everything it asks of a group to the second, so a caller
// adds its columns, its grouping on the fold and its order, and nothing else.
//
// The second level reads the partial groups under the alias "f", so the
// issue, the component and the build keep their names and every expression
// over them reads the same at either level.
func (f Filter) folded(db bun.IDB, rows *bun.SelectQuery,
	keyed func(*bun.SelectQuery) *bun.SelectQuery) *bun.SelectQuery {

	inner := placeHeads(keyed(f.narrowRows(rows)))
	if f.DiffersBetweenBuilds && f.Builds > 1 {
		inner = inner.ColumnExpr("f.target_id").GroupExpr("f.target_id")
	}
	inner = f.partials(inner)
	outer := db.NewSelect().
		TableExpr(`(?) AS "f"`, inner).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`)
	return f.narrowGroups(outer, overParts)
}

// placeHeads selects the first-level columns every second level reads: how
// many places a partial group holds, their highest urgency and the two
// exploitation flags, under the names the overParts spellings read.
func placeHeads(q *bun.SelectQuery) *bun.SelectQuery {
	return q.ColumnExpr(overRows.places() + ` AS "n"`).
		ColumnExpr(overRows.peak() + ` AS "peak"`).
		ColumnExpr(overRows.exploited() + ` AS "hit"`).
		ColumnExpr(overRows.exploitedHere() + ` AS "hit_here"`)
}

// byIssueAndComponent is the first level's keys for a list inside one product.
func byIssueAndComponent(q *bun.SelectQuery) *bun.SelectQuery {
	return q.ColumnExpr("f.vulnerability_id").ColumnExpr("f.component_id").
		GroupExpr("f.vulnerability_id, f.component_id")
}

// partials selects the first-level aggregates the filter's group conditions
// and its order read, and no others: each is a column computed over every open
// row of the selection.
func (f Filter) partials(q *bun.SelectQuery) *bun.SelectQuery {
	if f.HasFix {
		q = q.ColumnExpr(`MIN(f.fixed_in) AS "fixed_in"`).
			ColumnExpr(withFixAcross + ` AS "with_fix"`)
	}
	if f.Unconfirmed {
		q = q.ColumnExpr(`MIN(f.matched) AS "matched"`)
	}
	if f.OpenedAfter != nil || f.OpenedBefore != nil || f.SortBy == ByAge {
		q = q.ColumnExpr(`MIN(f.opened_at) AS "opened_at"`)
	}
	if f.ClosedAfter != nil {
		q = q.ColumnExpr(`MAX(f.closed_at) AS "closed_at"`)
	}
	if f.Overdue || f.DueBefore != nil || f.SortBy == ByDeadline {
		q = q.ColumnExpr(`MIN(f.due_at) AS "due_at"`)
	}
	if len(f.fixStates()) > 0 {
		q = q.ColumnExpr(`MIN(f.fix_state) AS "fix_least"`).
			ColumnExpr(`MAX(f.fix_state) AS "fix_most"`)
	}
	if len(trimmed(f.Assigned)) > 0 {
		q = q.ColumnExpr(`COUNT(f.assigned_to) AS "held"`).
			ColumnExpr(`MIN(f.assigned_to) AS "held_least"`).
			ColumnExpr(`MAX(f.assigned_to) AS "held_most"`)
	}
	// The columns of the table byState joins, wherever it joins it.
	if len(trimmed(f.States)) > 0 || len(trimmed(f.Outcomes)) > 0 || f.Planned != PlannedEither {
		for _, flag := range []string{"waiting", "approved", "lapsed", "planned", "this_outcome"} {
			q = q.ColumnExpr(overRows.decided(flag) + ` AS "` + flag + `"`)
		}
	}
	return q
}
