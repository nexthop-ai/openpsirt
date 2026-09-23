// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// opened back-dates when a finding was first seen, which is the far end of
// every wait this file measures and the only part of one a test can set.
func (f *fixture) opened(t *testing.T, findingID int64, when time.Time) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
		Set("opened_at = ?", when.Truncate(time.Microsecond)).
		Where("id = ?", findingID).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestAWaitIsMeasuredFromTheFindingTheDecisionIsAbout(t *testing.T) {
	// A place is a pair of names with no product in it, so the same place
	// sits in every product shipping that component — and a finding this
	// reader may not see sits at it too. Either one reaching the join makes
	// the figure a disclosure as well as wrong.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		now := time.Now().UTC()
		ours := f.build(t, f.product, "2026.03")
		libfoo := f.component(t, "libfoo", "1.2.3")

		mine := f.finds(t, ours, libfoo, "place-of-libfoo", access.Public)
		f.opened(t, mine, now.Add(-48*time.Hour))
		// Undisclosed, at the same place, in the same product. This reader
		// holds public triage and may not see it.
		hidden := f.finds(t, ours, libfoo, "place-of-libfoo", access.Private)
		f.opened(t, hidden, now.AddDate(0, 0, -10))

		other, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "other", "Other")
		if err != nil {
			t.Fatal(err)
		}
		theirs := f.build(t, other.ID, "2026.03")
		f.opened(t, f.finds(t, theirs, libfoo, "place-of-libfoo", access.Public),
			now.AddDate(0, 0, -30))

		at := f.at()
		at.PlaceIdentity = "place-of-libfoo"
		at.ConsumerUpstream = ""
		f.claims(t, at)
		// A second claim about a place nothing was ever found at, which is
		// what keeps the join outer: the claim still happened.
		nowhere := f.at()
		nowhere.PlaceIdentity = "place-of-nothing"
		nowhere.ConsumerUpstream = ""
		f.claims(t, nowhere)

		measured, err := f.store.Measure(ctx, f.reviewer, triage.Measuring{}, time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if measured.Sampled != 2 {
			t.Errorf("%d decisions measured, want both — a claim about a place with no "+
				"finding is a claim that still happened", measured.Sampled)
		}
		if len(measured.ToDecide) != 1 {
			t.Fatalf("%d bands waited, want one", len(measured.ToDecide))
		}
		waited := measured.ToDecide[0]
		if waited.Count != 1 {
			t.Fatalf("%d waits measured, want the one finding this reader may see here",
				waited.Count)
		}
		if waited.Median < 47*time.Hour || waited.Median > 50*time.Hour {
			t.Errorf("the wait reads as %s, want about two days — the figure is being "+
				"taken from a finding in another product or one this reader may not see",
				waited.Median)
		}
	})
}

func TestAPercentileIsTheValueAtOrPastThatPosition(t *testing.T) {
	// Nearest rank: the first observation at or past p of the way through.
	// Truncating instead picks the one below it, which for an odd count is
	// not the middle and for a tail figure is not the tail.
	days := func(of ...int) []time.Duration {
		out := make([]time.Duration, 0, len(of))
		for _, each := range of {
			out = append(out, time.Duration(each)*24*time.Hour)
		}
		return out
	}
	for _, each := range []struct {
		name   string
		sorted []time.Duration
		part   float64
		want   time.Duration
	}{
		{"an odd count's median is the middle one", days(1, 2, 30), 0.5, 48 * time.Hour},
		{"an even count's median is the upper of the two middles",
			days(1, 2, 3, 4), 0.5, 48 * time.Hour},
		{"a p90 over seven is the worst of them", days(1, 2, 3, 4, 5, 6, 7), 0.9, 168 * time.Hour},
		{"a p90 over ten is the ninth", days(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), 0.9, 216 * time.Hour},
		{"one observation is its own median", days(5), 0.5, 120 * time.Hour},
		{"nothing measured is no duration", nil, 0.5, 0},
	} {
		t.Run(each.name, func(t *testing.T) {
			if got := triage.NearestRank(each.sorted, each.part); got != each.want {
				t.Errorf("the position reads as %s, want %s", got, each.want)
			}
		})
	}
}
