// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"math"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// A page of a list held in memory is the rows the limit and the offset name,
// and an offset at or past the end, however large, is an empty page.
func TestAWindowIsTheRowsItNamesAndEmptyPastTheEnd(t *testing.T) {
	rows := []int{1, 2, 3, 4, 5}
	for _, c := range []struct {
		name          string
		limit, offset int
		want          []int
	}{
		{"the first page", 2, 0, []int{1, 2}},
		{"a middle page", 2, 2, []int{3, 4}},
		{"a short last page", 2, 4, []int{5}},
		{"an offset at the end", 2, 5, []int{}},
		{"an offset near the largest integer", math.MaxInt, math.MaxInt, []int{}},
		{"a limit near the largest integer", math.MaxInt, 3, []int{4, 5}},
		{"a negative offset", 2, -1, []int{1, 2}},
		{"a negative limit", -1, 0, []int{}},
	} {
		if got := core.Window(rows, c.limit, c.offset); !slices.Equal(got, c.want) {
			t.Errorf("%s answered %v, want %v", c.name, got, c.want)
		}
	}
}
