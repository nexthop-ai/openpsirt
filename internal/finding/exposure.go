// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ErrNotOneBuild is a read about one build asked of a selection that is not
// exactly one build the reader may read.
var ErrNotOneBuild = errors.New("the selection is not one build")

// Held is what a selection held open at one moment, counted as the trend
// counts: issues at components, by the component's identifying name.
type Held struct {
	At   time.Time
	Open int
	// BySeverity is Open split by the strictest band any open finding of the
	// issue held.
	BySeverity map[string]int
}

// OneBuild is the build a scope names, where the subject may read it.
//
// A selection naming several builds, or none the subject may read, is refused
// with ErrNotOneBuild: a chart of whichever build sorted first is a chart of
// somewhere else.
func (s *Store) OneBuild(ctx context.Context, subject access.Subject, scope Scope) (int64, error) {
	if subject.Kind != access.Person {
		return 0, access.Denied("read a build's exposure over its uploads")
	}
	products, all := subject.Products()
	builds, err := s.readableBuilds(ctx, scope, products, all)
	if err != nil {
		return 0, err
	}
	if len(builds) != 1 {
		return 0, refusal.Errorf("%w: a build's uploads are one build's, and %d builds are in scope",
			ErrNotOneBuild, len(builds))
	}
	return builds[0], nil
}

// OpenAt counts, at each of these moments, the issues at components open in
// the scope, split by severity, in the order the moments were given.
//
// An issue is open at a moment when one of its findings opened at or before it
// and closed after it, or not at all: the trend's rule, so a point here and a
// step there ending at the same moment agree. The findings are read once, from
// the earliest moment through now, so the cost follows the earliest moment.
func (s *Store) OpenAt(ctx context.Context, subject access.Subject, scope Scope, within Within,
	moments []time.Time) ([]Held, error) {

	if subject.Kind != access.Person {
		return nil, access.Denied("read a build's exposure over its uploads")
	}
	out := make([]Held, len(moments))
	for i, at := range moments {
		out[i] = Held{At: at, BySeverity: map[string]int{}}
	}
	products, all := subject.Products()
	if len(moments) == 0 || (!all && len(products) == 0) {
		return out, nil
	}
	narrow, builds, err := s.trendNarrowing(ctx, subject, products, all, scope, within)
	if err != nil {
		return nil, err
	}
	earliest := slices.MinFunc(moments, func(a, b time.Time) int { return a.Compare(b) })
	// The rows open at the earliest moment or opened since: trendMoments reads
	// those still open after a moment, and one closed exactly at the earliest
	// moment is gone by it.
	rows, err := s.trendMoments(ctx, narrow, within, builds, earliest)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key().less(rows[j].key()) })

	open := make([]bool, len(moments))
	rank := make([]int, len(moments))
	band := make([]string, len(moments))
	for i := 0; i < len(rows); {
		id := rows[i].key()
		clear(open)
		clear(rank)
		clear(band)
		for ; i < len(rows) && rows[i].key() == id; i++ {
			row := rows[i]
			r := Ranks(row.Severity)
			for k, at := range moments {
				if row.OpenedAt.After(at) || (row.ClosedAt != nil && !row.ClosedAt.After(at)) {
					continue
				}
				// An issue open at two of its components' versions, or in two
				// products, takes the strictest band, as the trend's open does.
				if !open[k] || r > rank[k] {
					open[k], rank[k], band[k] = true, r, row.Severity
				}
			}
		}
		for k := range moments {
			if open[k] {
				out[k].Open++
				out[k].BySeverity[band[k]]++
			}
		}
	}
	return out, nil
}
