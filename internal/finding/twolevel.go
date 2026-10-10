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

// partKey is one key of the first level: the expression a partial group is
// grouped on, and the column it is selected as. The second level and the
// decided places beside the first level read it by that name.
type partKey struct {
	expr string
	args []any
	name string
}

// keyedBy selects the keys and groups on them.
func keyedBy(q *bun.SelectQuery, keys []partKey) *bun.SelectQuery {
	for _, key := range keys {
		q = q.ColumnExpr(key.expr+` AS "`+key.name+`"`, key.args...).GroupExpr(key.expr, key.args...)
	}
	return q
}

// folded is the first level of the two-level form joined to the component, as
// a query a caller groups on the fold and selects from.
//
// rows is the population: open findings of the selection, read as "f", with
// whatever joins the caller's own conditions need. keys are the first level's
// grouping keys; the issue and the component are always among them.
// Everything the filter asks of a place is applied to the first level and
// everything it asks of a group to the second, so a caller adds its columns,
// its grouping on the fold and its order, and nothing else.
//
// The second level reads the partial groups under the alias "f", so the
// issue, the component and the build keep their names and every expression
// over them reads the same at either level.
func (f Filter) folded(db bun.IDB, rows *bun.SelectQuery, keys []partKey) *bun.SelectQuery {
	if f.DiffersBetweenBuilds && f.Builds > 1 {
		keys = append(keys[:len(keys):len(keys)], partKey{expr: "f.target_id", name: "target_id"})
	}
	var inner *bun.SelectQuery
	if f.asksDecided() {
		inner = f.decidedBeside(db, rows, keys)
	} else {
		inner = f.partials(placeHeads(keyedBy(f.narrowRows(rows), keys)))
	}
	outer := db.NewSelect().
		TableExpr(`(?) AS "f"`, inner).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`)
	return f.narrowGroups(outer, overParts)
}

// decidedBeside is the first level of a filter that asks how far a group has
// been decided: the partial groups, each with how many of its places carry
// each decision flag, folded together on the partial group's keys.
//
// The flags are counted over the decided places alone. The decision table is
// built from the decisions outward over the same population the partial groups
// read, with every condition on a place applied, and folded to the first
// level's keys. Joined to every open place instead, each of a product's 368,847
// open rows is looked up in a table of 148,102 decided places, and the partial
// groups can no longer be read from finding's covering index: 1,067 ms against
// 575 ms for a build's unsettled work on PostgreSQL with 133,549 decisions.
func (f Filter) decidedBeside(db bun.IDB, rows *bun.SelectQuery, keys []partKey) *bun.SelectQuery {
	apart := f
	apart.decidedApart = true
	columns := append(append([]partColumn{}, headColumns...), apart.partialColumns()...)
	parts := selecting(keyedBy(apart.narrowRows(rows.Clone()), keys), columns)

	// One row per place in the population, carrying what the match to a
	// decision reads and the keys it is folded to. The issues a filter needing
	// a decision can reach are stated on the decisions rather than here: a
	// planner estimates the match between a decision and a place as the
	// product of two equalities that are not independent, a tenth to a
	// twentieth of the rows it produces, and with the population narrowed as
	// well PostgreSQL took the small side for the outer one and probed the
	// place index once per decision, 2.7 s for the lapsed tile where the
	// places hashed take 0.42 s. A decided place outside those issues joins
	// no partial group, because the partial groups are narrowed to them.
	whole := apart
	whole.decidedIssues = nil
	population := whole.narrowRows(rows).
		ColumnExpr(`f.id AS "id"`).
		ColumnExpr(`f.place_identity AS "place_identity"`).
		ColumnExpr(`f.consumer_id AS "consumer_id"`)
	for _, key := range keys {
		population = population.ColumnExpr(key.expr+` AS "`+key.name+`"`, key.args...)
	}
	places := f.flagColumns(decisionsOver(db.NewSelect(), `(?) AS "f2"`, population))
	// A condition comparing a count of decided places with the places a group
	// holds needs each place counted once, so the decisions are folded to the
	// place before they are folded to the keys. Every other condition asks
	// whether any place carries a flag or none does, which a fold straight to
	// the keys answers the same: with the flag at most one per partial group
	// instead of one per place, "more than none" and "none" are unchanged. It
	// skips grouping 148,102 decided places one at a time: 726 ms against
	// 635 ms for the undecided page's grouping on PostgreSQL.
	perPlace := f.comparesDecidedPlaces()
	if perPlace {
		places = places.GroupExpr("f2.id")
	}
	if f.decidedIssues != nil {
		places = f.amongDecidedIssues(places, "dv.issue_id")
	}
	if f.Across {
		// Across products each place carries its own product, and the decision
		// has to belong to the product the place sits in.
		named := false
		for _, key := range keys {
			named = named || key.name == "product_id"
		}
		if !named {
			panic("finding: a first level across products is keyed on the product")
		}
		places = places.Where("de.product_id = f2.product_id")
	} else {
		places = places.Where("de.product_id = ?", f.ProductID)
	}
	for _, key := range keys {
		places = places.ColumnExpr(`f2.` + key.name + ` AS "` + key.name + `"`).GroupExpr("f2." + key.name)
	}
	decided := places
	if perPlace {
		decided = db.NewSelect().TableExpr(`(?) AS "dp"`, places)
		for _, key := range keys {
			decided = decided.ColumnExpr(`dp.` + key.name).GroupExpr("dp." + key.name)
		}
		for _, flag := range decidedFlags {
			decided = decided.ColumnExpr(`SUM(dp.` + flag + `) AS "` + flag + `"`)
		}
	}

	// The partial groups and the decided ones are put together by stacking
	// the two and folding them on the keys, rather than by joining one to the
	// other. Joined on the keys, MariaDB read the decided groups as a table to
	// work out again for each partial group it was joined to, and re-ran the
	// decisions 12,260 times: 71 s where the list across products takes 0.37 s.
	// Stacked, each side is worked out once on every engine. Each side has
	// every column, in one order: the decided groups' aggregates are none where
	// they fold by a sum and absent where they fold by a minimum or a maximum.
	// The decided side is an arm of the union itself rather than a table read
	// by one, so an absent value takes its type from the partial groups'
	// column.
	others := db.NewSelect().TableExpr(`(?) AS "d"`, decided)
	for _, key := range keys {
		others = others.ColumnExpr(`d.` + key.name + ` AS "` + key.name + `"`)
	}
	for _, column := range columns {
		none := "NULL"
		if column.fold == "SUM" {
			none = "0"
		}
		others = others.ColumnExpr(none + ` AS "` + column.name + `"`)
	}
	for _, flag := range decidedFlags {
		parts = parts.ColumnExpr(`0 AS "` + flag + `"`)
		others = others.ColumnExpr(`d.` + flag + ` AS "` + flag + `"`)
	}
	stacked := db.NewSelect().
		TableExpr(`(SELECT * FROM (?) AS "parts" UNION ALL ?) AS "u"`, parts, others)
	for _, key := range keys {
		stacked = stacked.ColumnExpr(`u.` + key.name + ` AS "` + key.name + `"`).GroupExpr("u." + key.name)
	}
	for _, column := range columns {
		stacked = stacked.ColumnExpr(column.fold + `(u.` + column.name + `) AS "` + column.name + `"`)
	}
	for _, flag := range decidedFlags {
		stacked = stacked.ColumnExpr(`SUM(u.` + flag + `) AS "` + flag + `"`)
	}
	// A decided group always has places in the partial groups, because both
	// read the same population; a group with none is not one the list holds.
	return stacked.Having("SUM(u.n) > 0")
}

// comparesDecidedPlaces is whether a condition the filter asks of a group
// compares how many places carry a decision flag with how many places it has:
// agreed, and an outcome, which hold where every place does.
func (f Filter) comparesDecidedPlaces() bool {
	if len(trimmed(f.Outcomes)) > 0 {
		return true
	}
	for _, state := range trimmed(f.States) {
		if state == StandingAgreed {
			return true
		}
	}
	return false
}

// partColumn is one aggregate of the first level: the expression over the
// places, how the values of two partial groups fold together, and the column
// it is selected as.
type partColumn struct {
	expr string
	fold string
	name string
}

// headColumns is the first-level columns every second level reads: how many
// places a partial group holds, their highest urgency and the two exploitation
// flags, under the names the overParts spellings read.
var headColumns = []partColumn{
	{overRows.places(), "SUM", "n"},
	{overRows.peak(), "MAX", "peak"},
	{overRows.exploited(), "MAX", "hit"},
	{overRows.exploitedHere(), "MAX", "hit_here"},
}

// selecting selects each column's expression under its name.
func selecting(q *bun.SelectQuery, columns []partColumn) *bun.SelectQuery {
	for _, column := range columns {
		q = q.ColumnExpr(column.expr + ` AS "` + column.name + `"`)
	}
	return q
}

// placeHeads selects headColumns.
func placeHeads(q *bun.SelectQuery) *bun.SelectQuery {
	return selecting(q, headColumns)
}

// issueAndComponent is the first level's keys for a list inside one product.
var issueAndComponent = []partKey{
	{expr: "f.vulnerability_id", name: "vulnerability_id"},
	{expr: "f.component_id", name: "component_id"},
}

// partials selects partialColumns.
func (f Filter) partials(q *bun.SelectQuery) *bun.SelectQuery {
	return selecting(q, f.partialColumns())
}

// partialColumns is the first-level aggregates the filter's group conditions
// and its order read, and no others: each is a column computed over every open
// row of the selection.
func (f Filter) partialColumns() []partColumn {
	var columns []partColumn
	if f.HasFix {
		columns = append(columns, partColumn{"MIN(f.fixed_in)", "MIN", "fixed_in"},
			partColumn{withFixAcross, "SUM", "with_fix"})
	}
	if f.Unconfirmed {
		columns = append(columns, partColumn{"MIN(f.matched)", "MIN", "matched"})
	}
	if f.OpenedAfter != nil || f.OpenedBefore != nil || f.SortBy == ByAge {
		columns = append(columns, partColumn{"MIN(f.opened_at)", "MIN", "opened_at"})
	}
	if f.ClosedAfter != nil {
		columns = append(columns, partColumn{"MAX(f.closed_at)", "MAX", "closed_at"})
	}
	if f.Overdue || f.DueBefore != nil || f.SortBy == ByDeadline {
		columns = append(columns, partColumn{"MIN(f.due_at)", "MIN", "due_at"})
	}
	if len(f.fixStates()) > 0 {
		columns = append(columns, partColumn{"MIN(f.fix_state)", "MIN", "fix_least"},
			partColumn{"MAX(f.fix_state)", "MAX", "fix_most"})
	}
	if len(trimmed(f.Assigned)) > 0 {
		columns = append(columns, partColumn{"COUNT(f.assigned_to)", "SUM", "held"},
			partColumn{"MIN(f.assigned_to)", "MIN", "held_least"},
			partColumn{"MAX(f.assigned_to)", "MAX", "held_most"})
	}
	// The decision flags are not among them: a filter asking how far a group
	// has been decided counts its decided places beside the first level (see
	// decidedBeside).
	return columns
}
