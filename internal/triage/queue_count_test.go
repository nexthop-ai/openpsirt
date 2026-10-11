// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Every count the review queue gives is the number of claims its list holds:
// a claim with several rows is one, and a claim with any row out of the
// reader's reach is none. The approval count, the page's total, the number
// beside a product and an expired deferral's count are each asked.
func TestAQueueCountIsTheWholeClaimsTheReaderMayActOn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		insider := f.privately(t)

		// Waiting for approval: two undisclosed claims, one of them over three
		// places, one claim with a disclosed row beside an undisclosed one,
		// and one wholly disclosed.
		private := f.proposes(t, insider, f.placeIn(f.product, "under-a", access.Private))
		wide := f.proposes(t, insider,
			f.placeIn(f.product, "under-b", access.Private),
			f.placeIn(f.product, "under-c", access.Private),
			f.placeIn(f.product, "under-d", access.Private))
		mixed := f.proposes(t, insider,
			f.placeIn(f.product, "under-e", access.Private),
			f.placeIn(f.product, "under-f", access.Public))
		f.proposes(t, f.triager, f.placeIn(f.product, "under-g", access.Public))

		approver := f.holding(t, "private-approver", map[int64][]access.Role{
			f.product: {access.PrivateRead, access.Approver},
		})
		want := []int64{private.ClaimID, wide.ClaimID}
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
			t.Errorf("the queue lists claims %v, want %v (the claim with a disclosed row is %d)",
				listed, want, mixed.ClaimID)
		}
		for _, one := range []struct {
			name string
			n    int
		}{{"the count", counted}, {"a page's total", total}, {"the number beside the product", beside}} {
			if one.n != len(want) {
				t.Errorf("%s is %d, want %d whole claims", one.name, one.n, len(want))
			}
		}
		if len(page) != 1 || page[0].Claim.ID != slices.Max(want) {
			t.Errorf("a page of one holds %d claims, want the newest, %d", len(page), slices.Max(want))
		}

		// An expired deferral asks for a new decision, of whoever may decide
		// every row of it.
		defers := func(places ...triage.Place) int64 {
			t.Helper()
			soon := time.Now().UTC().Add(24 * time.Hour)
			var proposals []triage.Proposal
			for _, at := range places {
				proposals = append(proposals, triage.Proposal{
					Place: at, Outcome: triage.Deferred, Reasoning: "Not this sprint.",
					DeferredUntil: &soon, By: insider.ID,
				})
			}
			recorded, err := f.store.ProposeMany(ctx, insider, proposals)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.DB.NewUpdate().Table("claim").
				Set("deferred_until = ?", time.Now().UTC().Add(-time.Hour)).
				Where("id = ?", recorded[0].ClaimID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			return recorded[0].ClaimID
		}
		defers(f.placeIn(f.product, "deferred-a", access.Private),
			f.placeIn(f.product, "deferred-b", access.Public))
		disclosed := defers(f.placeIn(f.product, "deferred-c", access.Public),
			f.placeIn(f.product, "deferred-d", access.Public))
		decider := f.holding(t, "public-decider", map[int64][]access.Role{
			f.product: {access.PublicRead, access.PublicTriage},
		})
		expired := triage.QueueFilter{Reason: triage.DeferralExpired, ProductID: f.product}
		if _, n, err := f.store.Queue(ctx, decider, expired, 0, 0); err != nil || n != 1 {
			t.Errorf("the expired deferrals counted for a disclosed decider are %d (%v), want 1", n, err)
		}
		if got := f.listed(t, decider, expired); len(got) != 1 || got[0] != disclosed {
			t.Errorf("the expired deferrals listed for a disclosed decider are %v, want %d", got, disclosed)
		}
		if _, n, err := f.store.Queue(ctx, insider, expired, 0, 0); err != nil || n != 2 {
			t.Errorf("the expired deferrals counted for somebody deciding both are %d (%v), want 2", n, err)
		}
	})
}
