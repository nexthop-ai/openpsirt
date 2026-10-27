// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Every count the review queue gives is the number of decisions its list holds:
// a decision with several rows is one, and a decision with any row out of the
// reader's reach is none. The approval count, the page's total and the number
// beside a product are each asked.
func TestAQueueCountIsTheWholeDecisionsTheReaderMayActOn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		insider := f.privately(t)

		// Waiting for approval: two undisclosed decisions, one of them over three
		// occurrences, one decision with a disclosed row beside an undisclosed one,
		// and one wholly disclosed.
		private := f.proposes(t, insider, f.occurrenceIn(f.product, "under-a", access.Private))
		wide := f.proposes(t, insider,
			f.occurrenceIn(f.product, "under-b", access.Private),
			f.occurrenceIn(f.product, "under-c", access.Private),
			f.occurrenceIn(f.product, "under-d", access.Private))
		mixed := f.proposes(t, insider,
			f.occurrenceIn(f.product, "under-e", access.Private),
			f.occurrenceIn(f.product, "under-f", access.Public))
		f.proposes(t, f.triager, f.occurrenceIn(f.product, "under-g", access.Public))

		approver := f.holding(t, "private-approver", map[int64][]access.Role{
			f.product: {access.PrivateRead, access.Approver},
		})
		want := []int64{private.DecisionID, wide.DecisionID}
		slices.Sort(want)

		_, counted, err := f.store.Queue(ctx, approver, triage.QueueFilter{}, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		page, total, err := f.store.Queue(ctx, approver, triage.QueueFilter{ProductID: f.product}, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		beside, err := f.store.WaitingIn(ctx, approver, f.product)
		if err != nil {
			t.Fatal(err)
		}
		listed := f.listed(t, approver, triage.QueueFilter{})
		slices.Sort(listed)
		if !slices.Equal(listed, want) {
			t.Errorf("the queue lists decisions %v, want %v (the decision with a disclosed row is %d)",
				listed, want, mixed.DecisionID)
		}
		for _, one := range []struct {
			name string
			n    int
		}{{"the count", counted}, {"a page's total", total}, {"the number beside the product", beside}} {
			if one.n != len(want) {
				t.Errorf("%s is %d, want %d whole decisions", one.name, one.n, len(want))
			}
		}
		if len(page) != 1 || page[0].Decision.ID != slices.Max(want) {
			t.Errorf("a page of one holds %d decisions, want the newest, %d", len(page), slices.Max(want))
		}
	})
}
