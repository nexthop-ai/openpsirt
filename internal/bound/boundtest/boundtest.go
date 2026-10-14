// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package boundtest checks a size or count bound from both sides.
//
// A bound tested only past its limit passes when the bound is off by one in
// the generous direction, and passes again when the input is refused for some
// other reason. Feeding the limit itself and then one more pins the edge: the
// first has to be taken, the second refused, and refused by the bound.
package boundtest

import "testing"

// Edges feeds limit and then limit+1. The first must succeed and the second
// must fail with an error refused recognizes.
func Edges(t testing.TB, limit int, feed func(n int) error, refused func(error) bool) {
	t.Helper()
	if limit < 1 {
		t.Fatalf("a limit of %d leaves nothing to feed at the edge", limit)
	}
	if err := feed(limit); err != nil {
		t.Fatalf("at the limit (%d): %v", limit, err)
	}
	err := feed(limit + 1)
	if err == nil {
		t.Fatalf("past the limit (%d): taken, want a refusal", limit+1)
	}
	if !refused(err) {
		t.Fatalf("past the limit (%d): refused for another reason: %v", limit+1, err)
	}
}
