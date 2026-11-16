// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"regexp"
	"testing"
)

// Every order the list offers is one it actually sorts by.
//
// The two halves are a slice and a map, and a key in the slice with no entry
// in the map is the silent failure: it is accepted at the edge — the query
// parameter's own list is built from the slice — and then sorted by urgency
// instead, which looks like a list that simply did not reorder.
//
// Asked here, where the map is reachable, rather than through an exported
// helper whose only caller was the test asking it.
func TestEveryOfferedOrderHasAnExpression(t *testing.T) {
	if len(SortKeys()) == 0 || len(order) == 0 {
		t.Fatal("no sort key or no sort expression was found, so this checked nothing")
	}
	for _, key := range SortKeys() {
		if _, known := order[key]; !known {
			t.Errorf("%q is offered and the store sorts by nothing of that name", key)
		}
	}
	// And the other direction, which would be an expression nothing can ask
	// for: a key the store knows and the parameter never offers.
	offered := map[SortKey]bool{}
	for _, key := range SortKeys() {
		offered[key] = true
	}
	for key := range order {
		if !offered[key] {
			t.Errorf("%q is an order the store knows and nothing offers", key)
		}
	}
}

// Every name a list order writes is quoted, the names its own statement
// invents included: an engine reserves a word only bare, and a string
// constant is out of the reserved-word report's sight.
func TestEveryListOrderQuotesTheNamesItWrites(t *testing.T) {
	var orders []string
	for _, ascending := range []bool{false, true} {
		orders = append(orders,
			plannedUpgradeSorted(Filter{Ascending: ascending}),
			componentOrder(Filter{Ascending: ascending}))
		for _, key := range PlannedUpgradeSortKeys() {
			orders = append(orders, plannedUpgradeSorted(Filter{PlannedUpgradeSort: key, Ascending: ascending}))
		}
		for _, key := range SortKeys() {
			orders = append(orders, componentOrder(Filter{SortBy: key, Ascending: ascending}))
		}
	}
	if len(orders) == 0 {
		t.Fatal("no order was built, so this checked nothing")
	}
	quoted := regexp.MustCompile(`"[^"]*"|'[^']*'`)
	bare := regexp.MustCompile(`\b[a-z_][a-z0-9_]*\b`)
	for _, sorted := range orders {
		if name := bare.FindString(quoted.ReplaceAllString(sorted, "")); name != "" {
			t.Errorf("%q writes %s bare", sorted, name)
		}
	}
}
