// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Reading is one point of a trend by build date: the moment each build in the
// scope is read at, and the builds whose first upload the point is.
//
// A build absent from Builds held no upload by the point's date, so it adds
// nothing to it.
type Reading struct {
	At     time.Time
	Builds map[int64]time.Time
	First  map[int64]bool
}

// TrendBuilds is the builds a trend over this scope reads, on products the
// subject may read, in identifier order.
func (s *Store) TrendBuilds(ctx context.Context, subject access.Subject, scope Scope) ([]int64, error) {
	if subject.Kind != access.Person {
		return nil, access.Denied("read how findings are trending")
	}
	products, all := subject.Products()
	return s.readableBuilds(ctx, scope, products, all)
}

// TrendAtReadings is the trend at these readings, oldest first: at each, the
// issues at components open in the scope, each build read at its own moment,
// and what moved since the reading before.
//
// An issue is open at a reading when, in some build the reading names, one of
// its findings opened at or before that build's moment and closed after it, or
// not at all: the trend's rule, applied to each build at its own moment. The
// unit, the severity an issue takes and the narrowing are the calendar
// trend's. The flows compare consecutive readings:
//
//   - new: open now, at no earlier reading, and held by a build that is not
//     first read here;
//   - baseline: open now for the first time, held only by builds first read
//     here;
//   - returned: open now, not at the reading before, open at an earlier one;
//   - corrected: open at the reading before, not now, and every one of its
//     findings that closed in between closed by a resolution.
//
// The first reading has nothing before it, so only its baseline moves. The
// findings are read once, from the earliest moment through now, so the cost
// follows the earliest moment.
func (s *Store) TrendAtReadings(ctx context.Context, subject access.Subject, scope Scope, within Within,
	readings []Reading) ([]Point, error) {

	if subject.Kind != access.Person {
		return nil, access.Denied("read how findings are trending")
	}
	points := make([]Point, len(readings))
	for k, r := range readings {
		points[k] = Point{At: r.At, BySeverity: map[string]int{}, NewBySeverity: map[string]int{},
			CorrectedBySeverity: map[string]int{}, ReturnedBySeverity: map[string]int{}}
		for build, first := range r.First {
			if _, read := r.Builds[build]; first && read {
				points[k].FirstScans++
			}
		}
	}
	products, all := subject.Products()
	var earliest time.Time
	for _, r := range readings {
		for _, at := range r.Builds {
			if earliest.IsZero() || at.Before(earliest) {
				earliest = at
			}
		}
	}
	if earliest.IsZero() || (!all && len(products) == 0) {
		return points, nil
	}
	narrow, builds, err := s.trendNarrowing(ctx, subject, products, all, scope, within)
	if err != nil {
		return nil, err
	}
	rows, err := s.momentsOf(ctx, narrow, within, builds, earliest, true)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key().less(rows[j].key()) })

	n := len(readings)
	open := make([]bool, n)
	rank := make([]int, n)
	band := make([]string, n)
	// fresh[k] is whether every build holding the issue at reading k is first
	// read there.
	fresh := make([]bool, n)
	// quiet[k] is whether a finding open at reading k-1 closed before reading
	// k by something other than a resolution.
	quiet := make([]bool, n)
	openAt := func(row trendRow, at time.Time) bool {
		return !row.OpenedAt.After(at) && (row.ClosedAt == nil || row.ClosedAt.After(at))
	}
	for i := 0; i < len(rows); {
		id := rows[i].key()
		clear(open)
		clear(rank)
		clear(band)
		clear(quiet)
		for k := range fresh {
			fresh[k] = true
		}
		for ; i < len(rows) && rows[i].key() == id; i++ {
			row := rows[i]
			r := Ranks(row.Severity)
			for k, reading := range readings {
				at, read := reading.Builds[row.BuildID]
				if !read {
					continue
				}
				if openAt(row, at) {
					// An issue open at two of its components' versions, or in
					// two builds, takes the strictest band, as the trend's
					// open does.
					if !open[k] || r > rank[k] {
						open[k], rank[k], band[k] = true, r, row.Severity
					}
					if !reading.First[row.BuildID] {
						fresh[k] = false
					}
				}
				if k == 0 {
					continue
				}
				// Open when this build was read before, gone by now, and not
				// by a fix: the departure is no correction.
				before, readBefore := readings[k-1].Builds[row.BuildID]
				if readBefore && openAt(row, before) && !openAt(row, at) &&
					row.ClosedAt != nil && !Closure(row.ClosedBecause).Resolves() {
					quiet[k] = true
				}
			}
		}
		for k := range readings {
			if open[k] {
				points[k].Open++
				points[k].BySeverity[band[k]]++
			}
			was := k > 0 && open[k-1]
			switch {
			case open[k] && !was:
				switch {
				case slices.Contains(open[:max(k-1, 0)], true):
					points[k].Returned++
					points[k].ReturnedBySeverity[band[k]]++
				case fresh[k]:
					points[k].Baseline++
				case k > 0:
					points[k].New++
					points[k].NewBySeverity[band[k]]++
				}
			case was && !open[k] && !quiet[k]:
				points[k].Corrected++
				points[k].CorrectedBySeverity[band[k-1]]++
			}
		}
	}
	return points, nil
}
