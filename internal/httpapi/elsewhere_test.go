// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestAClaimSaysWhereTheWorkIsHappening(t *testing.T) {
	// A hand-off to a tracker needs no deployment to decide to let anything
	// out: a stored link has no egress at all, and it connects what is
	// decided here to the work being done there.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200",
			`{"outcome":"affected","reasoning":"Reachable from the request path."}`)

		// The claim points at where it is being worked on.
		if got := asPerson(t, r, "triager", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/elsewhere", claim),
			`{"elsewhere":"https://tracker.example/PSIRT-42"}`); got.Code != http.StatusNoContent {
			t.Fatalf("pointing the claim answered %d: %s", got.Code, got.Body.String())
		}
		var standing struct {
			Standing []struct {
				Elsewhere string `json:"elsewhere"`
			} `json:"standing"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &standing)
		if len(standing.Standing) != 1 || standing.Standing[0].Elsewhere == "" {
			t.Errorf("the finding does not say where the work is: %+v", standing.Standing)
		}

		// Somebody who may only read it cannot point it anywhere.
		refusedWith(t, asPerson(t, r, "reader", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/elsewhere", claim),
			`{"elsewhere":"https://elsewhere.example/1"}`), http.StatusNotFound)

		// An address nobody should be handed as a link is refused in words
		// naming it, and is not a fault here.
		for _, address := range []string{"ms-msdt:calc", "//evil.example/x"} {
			got := asPerson(t, r, "triager", http.MethodPut,
				fmt.Sprintf("/v1/claims/%d/elsewhere", claim),
				fmt.Sprintf(`{"elsewhere":%q}`, address))
			if got.Code != http.StatusUnprocessableEntity {
				t.Errorf("pointing the claim at %s answered %d: %s", address, got.Code, got.Body.String())
			}
		}
		if got := asPerson(t, r, "triager", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/elsewhere", claim),
			`{"elsewhere":"ms-msdt:calc"}`); !strings.Contains(got.Body.String(), "ms-msdt") {
			t.Errorf("the refusal does not name the scheme: %s", got.Body.String())
		}
	})
}
