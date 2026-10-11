// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// SortKey is a column somebody may order the findings list by.
//
// An allowlist, and the allowlist is the only thing that reaches the
// statement. A placeholder cannot bind a column name, so a sort
// column arriving from a query parameter is the one value that must reach the
// SQL text — which makes it the live hole in a codebase that parameterizes
// everything else. Nothing here is built from what a caller
// typed: a key that is not one of these is not a sort, and the answer is the
// default order rather than an error, because an unknown sort is a caller's
// mistake about a list rather than a refusal to show it.
//
// It is also what keeps a sort from exposing a column nobody was meant to
// order by, which is a quieter version of the same problem.
type SortKey string

const (
	// ByUrgency is the default and the one the list is designed around: what
	// somebody with an hour should look at first.
	ByUrgency SortKey = "urgency"
	// ByAge is how long this has been open here, which is the age a deadline
	// relates to.
	ByAge SortKey = "age"
	// ByDeadline is when it runs out. Findings with none sort last whichever
	// direction is asked for: "no deadline" is not early and not late.
	ByDeadline SortKey = "deadline"
	// ByPlaces is how far it reaches, which is what says whether one judgment
	// answers a lot or a little.
	ByPlaces SortKey = "places"
	// ByLikelihood is the published estimate that it will be exploited, which
	// ranks above severity and is how a batch of "worth doing now" is built.
	ByLikelihood SortKey = "epss"
	// BySeverity is the rating in force, as the number the ordering compares
	// rather than the word.
	BySeverity SortKey = "severity"
)

// order is the expression each key sorts by, whether it needs the issue
// joined, and whether the expression is the name of a column every grouped
// page selects. Keyed by the constant rather than by a string a caller
// supplies: what reaches the statement is this map's value, never its lookup.
var order = map[SortKey]struct {
	expr   string
	issue  bool
	column bool
}{
	ByUrgency:    {expr: "urgency", column: true},
	ByAge:        {expr: "MIN(f.opened_at)"},
	ByDeadline:   {expr: "MIN(f.due_at)"},
	ByPlaces:     {expr: "places", column: true},
	ByLikelihood: {expr: "MAX(COALESCE(v.likelihood_ppm, 0))", issue: true},
	BySeverity:   {expr: "MAX(COALESCE(v.score_centi, 0))", issue: true},
}

// orderedBy is what an asked-for key sorts by, with the direction applied and
// nothing else — the tie-break that makes paging stable differs per list and
// is the caller's to append.
//
// One builder rather than one per list. Three lists sort on the same six keys
// and each had written out the same lookup, the same direction and the same
// null-last case, so a key that behaved differently on one of them was a
// difference nobody could see.
//
// The expression comes from the allowlist and never from the request. A
// caller's key that is not in it falls back to the one named here, which is
// each list's own default rather than a shared one.
//
// A finding with no deadline sorts last whichever way it is asked, because "no
// deadline" is not early and not late. That is spelled as a leading
// null-ordering column rather than as NULLS LAST, which two of the four
// engines do not have.
func orderedBy(filter Filter, fallback SortKey) string {
	by, known := order[filter.SortBy]
	if !known {
		by = order[fallback]
	}
	return directed(by.expr, filter.SortBy == ByDeadline, filter.Ascending)
}

// directed applies a direction to an expression the allowlist supplied, and
// puts what has no value last where the expression can have none.
//
// Sorting nothing last is spelled as a leading null-ordering column rather
// than as NULLS LAST, which two of the four engines do not have.
func directed(expr string, nothingLast, ascending bool) string {
	way := "DESC"
	if ascending {
		way = "ASC"
	}
	sorted := expr + " " + way
	if nothingLast {
		sorted = "CASE WHEN " + expr + " IS NULL THEN 1 ELSE 0 END, " + sorted
	}
	return sorted
}

// SortKeys are the orders somebody may ask for, in the order they are offered.
//
// One list. The query parameter's enum is built from this at registration and
// the interface's own union is generated from the document that enum produces,
// so an order added here is offered and an order removed here is refused,
// with nothing to keep in step by hand.
//
// The map above is keyed rather than ordered, which is why the ordering is
// written once here instead of being read back out of it.
func SortKeys() []SortKey {
	return []SortKey{ByUrgency, ByAge, ByDeadline, ByPlaces, ByLikelihood, BySeverity}
}

// pagedOrder is the ORDER BY a grouped page is read in through paged, and
// the expression the grouped statement selects as "sort_key" for it to order
// by. The expression is empty where the key is a column the page selects
// under the key's own name.
//
// Built from the allowlist alone. The only thing a caller decides is which of
// the fixed keys and which direction, and neither reaches the statement as
// text: the key selects a stored expression, and the direction selects one of
// two words written here.
//
// The tie-break is the columns the page is grouped on, always the same ones,
// so that paging is stable: two rows equal on the sorted column must not swap
// between pages, which drops one row and repeats another across a boundary.
func pagedOrder(filter Filter, tieBreak ...string) (key, sorted string) {
	by, known := order[filter.SortBy]
	if !known {
		by = order[ByUrgency]
	}
	column := `"paged"."sort_key"`
	key = by.expr
	if by.column {
		column, key = `"paged"."`+by.expr+`"`, ""
	}
	sorted = directed(column, filter.SortBy == ByDeadline, filter.Ascending)
	for _, name := range tieBreak {
		sorted += `, "paged"."` + name + `"`
	}
	return key, sorted
}
