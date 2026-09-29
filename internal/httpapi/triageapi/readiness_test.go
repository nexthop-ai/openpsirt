// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// TestReadinessSaysWhatIsBlocking is the list behind the count.
//
// "8 criticals now, v2.4.1 shipped with 4" is read at the moment there is no
// time to go and assemble what the 8 are, and the answer carried no list at
// all — so the one screen a release conversation happens in sent everybody
// back to the findings list to rebuild the same narrowing by hand.
func TestReadinessSaysWhatIsBlocking(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)

		const at = "/v1/products/mine/streams/master/variants/broadcom/readiness"
		ready := func(t *testing.T) struct {
			Blockers int `json:"blockers"`
			Blocking []struct {
				Vulnerability string `json:"vulnerability"`
				State         string `json:"state"`
				Places        int    `json:"places"`
			} `json:"blocking"`
		} {
			t.Helper()
			var out struct {
				Blockers int `json:"blockers"`
				Blocking []struct {
					Vulnerability string `json:"vulnerability"`
					State         string `json:"state"`
					Places        int    `json:"places"`
				} `json:"blocking"`
			}
			httpapitest.Read(t, r, "private-triage", at, &out)
			return out
		}

		first := ready(t)
		if first.Blockers != 2 || len(first.Blocking) != 2 {
			t.Fatalf("nothing is decided and the blocker list holds %d of %d",
				len(first.Blocking), first.Blockers)
		}
		if first.Blocking[0].State != "undecided" || first.Blocking[0].Places == 0 {
			t.Errorf("a blocker reads as %+v", first.Blocking[0])
		}

		// Agreeing to ship with something is the decision this list is about,
		// so it leaves: a row somebody agreed to is not standing between the
		// branch and the release.
		claim, _ := r.Claimed(t, "triager", "CVE-2026-9999", "linux-image", httpapitest.Dismissal)
		r.Agreed(t, claim)
		after := ready(t)
		if after.Blockers != 1 || len(after.Blocking) != 1 {
			t.Fatalf("after agreeing to one, %d of %d block",
				len(after.Blocking), after.Blockers)
		}
		if after.Blocking[0].Vulnerability != "CVE-2026-1000" {
			t.Errorf("the row somebody agreed to is still blocking: %+v", after.Blocking[0])
		}
	})
}

// TestBlockingRowsOfOneComponentAreToldApart pins the version on the row.
//
// A group is keyed on the issue and the fold, and a fold is the source package
// at the version it was built at — so one issue on one component at two
// versions is two rows. Named by component alone they arrive identical: the
// panel drew the same line twice, under the same React key, and a reader had
// no way to tell which of the two a row was about.
func TestBlockingRowsOfOneComponentAreToldApart(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedOneIssueAtTwoVersions(t)

		var out struct {
			Blocking []struct {
				Vulnerability string `json:"vulnerability"`
				Component     string `json:"component"`
				Version       string `json:"version"`
			} `json:"blocking"`
		}
		httpapitest.Read(t, r, "private-triage",
			"/v1/products/mine/streams/master/variants/broadcom/readiness", &out)

		if len(out.Blocking) != 2 {
			t.Fatalf("one issue at two versions of one component is %d rows", len(out.Blocking))
		}
		first, second := out.Blocking[0], out.Blocking[1]
		if first.Component != second.Component || first.Vulnerability != second.Vulnerability {
			t.Fatalf("the fixture stopped being one issue at one component: %+v %+v", first, second)
		}
		if first.Version == "" || second.Version == "" {
			t.Fatalf("a row carries no version: %+v %+v", first, second)
		}
		if first.Version == second.Version {
			t.Errorf("two rows of %q are identical at version %q",
				first.Component, first.Version)
		}
	})
}
