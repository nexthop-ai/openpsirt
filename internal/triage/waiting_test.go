// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The number beside a product is the length of the queue it links to.
//
// Counted apart from the queue, the two drift the first time the queue's
// population gains a condition, and a number that says something else from
// the screen it links to is worse than no number.
func TestWhatWaitsInAProductIsTheQueueForIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.claims(t, f.at())
		other := f.at()
		other.PlaceIdentity = "place-of-libfoo-under-libbaz"
		f.claims(t, other)

		for _, who := range []struct {
			name   string
			counts func() (int, int, error)
		}{
			{"the reviewer", func() (int, int, error) {
				counted, err := f.store.WaitingIn(ctx, f.reviewer, f.product)
				if err != nil {
					return 0, 0, err
				}
				_, listed, err := f.store.Queue(ctx, f.reviewer,
					triage.QueueFilter{ProductID: f.product}, 50, 0)
				return counted, listed, err
			}},
			{"the proposer", func() (int, int, error) {
				counted, err := f.store.WaitingIn(ctx, f.triager, f.product)
				if err != nil {
					return 0, 0, err
				}
				_, listed, err := f.store.Queue(ctx, f.triager,
					triage.QueueFilter{ProductID: f.product}, 50, 0)
				return counted, listed, err
			}},
		} {
			counted, listed, err := who.counts()
			if err != nil {
				t.Fatal(err)
			}
			if counted != listed {
				t.Errorf("for %s the product counts %d waiting and its queue lists %d",
					who.name, counted, listed)
			}
			if who.name == "the reviewer" && counted == 0 {
				t.Errorf("nothing is waiting on %s, so this compares nothing", who.name)
			}
		}
	})
}
