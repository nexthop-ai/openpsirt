// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"slices"
	"testing"
)

func TestChunksHoldTheirBoundAndAreNeverMoreThanTheMost(t *testing.T) {
	holding := func(rows ...int64) []buildHolding {
		out := make([]buildHolding, len(rows))
		for i, r := range rows {
			out[i] = buildHolding{BuildID: int64(i + 1), Rows: r}
		}
		return out
	}
	for name, one := range map[string]struct {
		held  []buildHolding
		bound int64
		want  [][]int64
	}{
		"small builds share one":     {holding(10, 10, 10), 100, [][]int64{{1, 2, 3}}},
		"a large build stands alone": {holding(10, 500, 10), 100, [][]int64{{1}, {2}, {3}}},
		"a chunk stops at its bound": {holding(60, 60, 30), 100, [][]int64{{1}, {2, 3}}},
		"no builds is no chunks":     {nil, 100, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if got := chunked(one.held, one.bound); !slices.EqualFunc(got, one.want, slices.Equal) {
				t.Errorf("chunked %v, want %v", got, one.want)
			}
		})
	}

	t.Run("many builds at the bound make no more than the most", func(t *testing.T) {
		rows := make([]int64, 1000)
		for i := range rows {
			rows[i] = 7
		}
		got := chunked(holding(rows...), 1)
		if len(got) > mostChunks {
			t.Errorf("%d chunks, want at most %d", len(got), mostChunks)
		}
		seen := 0
		for _, c := range got {
			seen += len(c)
		}
		if seen != len(rows) {
			t.Errorf("the chunks hold %d builds, want every one of %d", seen, len(rows))
		}
		// Counts the share does not divide evenly, which a share of the total
		// over mostChunks would split into more chunks than mostChunks.
		for _, n := range []int{51, 99} {
			if got := chunked(holding(slices.Repeat([]int64{7}, n)...), 1); len(got) > mostChunks {
				t.Errorf("%d builds: %d chunks, want at most %d", n, len(got), mostChunks)
			}
		}
	})
}
