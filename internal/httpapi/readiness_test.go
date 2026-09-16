package httpapi_test

import (
	"fmt"
	"net/http"
	"testing"
)

// TestReadinessSaysWhatIsBlocking is the list behind the count.
//
// "8 criticals now, v2.4.1 shipped with 4" is read at the moment there is no
// time to go and assemble what the 8 are, and the answer carried no list at
// all — so the one screen a release conversation happens in sent everybody
// back to the findings list to rebuild the same narrowing by hand.
func TestReadinessSaysWhatIsBlocking(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

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
			read(t, r, "private-triage", at, &out)
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
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}
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
