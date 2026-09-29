// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestTheQueueCardCarriesWhatWouldMakeAnApproverDisagree(t *testing.T) {
	// An approver was shown the claim and the reasoning and nothing that
	// argues against them, which is the rubber stamp the queue's shape was
	// written against — a weakness in a control rather than a card layout.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)

		// Something else at the same place that nobody has answered: the
		// fixture holds two issues at the one component.
		claim, _ := r.Claimed(t, "triager", "CVE-2026-9999", "linux-image", httpapitest.Dismissal)

		var queue struct {
			Items []struct {
				Claim struct {
					ID int64 `json:"id"`
				} `json:"claim"`
				Counter struct {
					Elsewhere map[string]int `json:"elsewhere"`
					Undecided int            `json:"undecided"`
				} `json:"counter"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reviewer", "/v1/review-queue", &queue)
		if len(queue.Items) != 1 {
			t.Fatalf("the queue holds %d claims", len(queue.Items))
		}
		if queue.Items[0].Counter.Undecided != 1 {
			t.Errorf("the card says %d other issues at that place are undecided, want 1",
				queue.Items[0].Counter.Undecided)
		}
		if len(queue.Items[0].Counter.Elsewhere) != 0 {
			t.Errorf("nothing has been agreed elsewhere yet: %+v", queue.Items[0].Counter)
		}

		// Now the other issue at the same place is agreed as affected, and a
		// second claim about the *first* issue is made somewhere else — which
		// is the material an approver is entitled to see.
		r.Agreed(t, claim)
		second, _ := r.Claimed(t, "triager", "CVE-2026-1000", "linux-image", httpapitest.Dismissal)

		// A fresh value rather than the one above: a zero count is left out of
		// the answer, so decoding into a struct that already held one keeps
		// the old number and the test asserts against its own memory.
		var after struct {
			Items []struct {
				Claim struct {
					ID int64 `json:"id"`
				} `json:"claim"`
				Counter struct {
					Elsewhere map[string]int `json:"elsewhere"`
					Undecided int            `json:"undecided"`
				} `json:"counter"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reviewer", "/v1/review-queue", &after)
		var found bool
		for _, item := range after.Items {
			if item.Claim.ID != second {
				continue
			}
			found = true
			// Nothing has been agreed about *this* issue elsewhere — the
			// approved claim was about the other one — so the card says
			// nothing rather than counting a neighbor as evidence.
			if len(item.Counter.Elsewhere) != 0 {
				t.Errorf("a decision about another issue was counted as one about this: %+v",
					item.Counter)
			}
			// And the place is no longer full of undecided work, because the
			// other issue there has been answered.
			if item.Counter.Undecided != 0 {
				t.Errorf("an answered neighbor is still counted as undecided: %+v",
					item.Counter)
			}
		}
		if !found {
			t.Fatalf("the second claim is not in the queue: %+v", after.Items)
		}
	})
}

func TestWhatWasAgreedAboutTheSameIssueElsewhereIsCounted(t *testing.T) {
	// The case worth a second look: a dismissal here where the same issue was
	// called affected somewhere else.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// Two packages of *different* source packages carrying one issue. It
		// has to be two folds: one judgment covers a whole fold, so two
		// different answers about one issue in one fold is not a state
		// anything can reach.
		r.ScannedTwoSources(t)

		// One package is called affected. Nobody has agreed to it yet.
		first, _ := r.Claimed(t, "triager", "CVE-2026-CURL1", "libcurl4t64",
			`{"outcome":"affected","reasoning":"Reachable from the request path."}`)
		// The other is dismissed, and its card is what an approver reads.
		second, _ := r.Claimed(t, "triager", "CVE-2026-CURL1", "libexpat1", httpapitest.Dismissal)

		counter := func(claim int64) map[string]int {
			t.Helper()
			// A fresh value each time: a count of zero is left out of the
			// answer, so a reused one keeps the last number decoded into it.
			var queue struct {
				Items []struct {
					Claim struct {
						ID int64 `json:"id"`
					} `json:"claim"`
					Counter struct {
						Elsewhere map[string]int `json:"elsewhere"`
					} `json:"counter"`
				} `json:"items"`
			}
			httpapitest.Read(t, r, "reviewer", "/v1/review-queue", &queue)
			for _, item := range queue.Items {
				if item.Claim.ID == claim {
					return item.Counter.Elsewhere
				}
			}
			t.Fatalf("claim %d is not in the queue: %+v", claim, queue.Items)
			return nil
		}

		// A proposal is one person's opinion and is not counted. Otherwise two
		// people in a queue would be counted at each other as evidence.
		if said := counter(second); len(said) != 0 {
			t.Errorf("an unapproved claim elsewhere was counted as evidence: %+v", said)
		}

		r.Agreed(t, first)
		if said := counter(second); said["affected"] == 0 {
			t.Errorf("the card does not say the same issue is affected elsewhere: %+v", said)
		}
	})
}
