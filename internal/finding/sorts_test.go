package finding

import "testing"

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
