package httpapi_test

import (
	"fmt"
	"net/http"
	"testing"
)

func TestAClaimAndAFixTargetSayWhereTheWorkIsHappening(t *testing.T) {
	// A hand-off to a tracker is two things and only one of them needs a
	// deployment to decide to let anything out: a stored link has no
	// egress at all, and it connects what is declared here to the work
	// being done there.
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
		if got := asPerson(t, r, "reader", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/elsewhere", claim),
			`{"elsewhere":"https://elsewhere.example/1"}`); got.Code < 400 {
			t.Errorf("somebody who may only read pointed a claim elsewhere: %d", got.Code)
		}

		// A fix target carries one too, and re-sending the plan without it
		// keeps what was recorded rather than erasing it.
		const targets = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/fix-targets"
		if got := asPerson(t, r, "triager", http.MethodPut, targets,
			`{"builds":[{"stream":"master","variant":"broadcom",`+
				`"elsewhere":"https://tracker.example/BUILD-7"}]}`); got.Code != http.StatusOK {
			t.Fatalf("declaring a fix answered %d: %s", got.Code, got.Body.String())
		}
		var plan struct {
			Items []struct {
				Stream    string `json:"stream"`
				State     string `json:"state"`
				Elsewhere string `json:"elsewhere"`
			} `json:"items"`
		}
		read(t, r, "triager", targets, &plan)
		var found string
		for _, one := range plan.Items {
			if one.Elsewhere != "" {
				found = one.Elsewhere
			}
		}
		if found != "https://tracker.example/BUILD-7" {
			t.Errorf("the fix target does not say where the work is: %+v", plan.Items)
		}

		// Re-sent without a link, what was recorded stays: a plan sent again
		// to add a release must not erase what the others said.
		if got := asPerson(t, r, "triager", http.MethodPut, targets,
			`{"builds":[{"stream":"master","variant":"broadcom"}]}`); got.Code != http.StatusOK {
			t.Fatalf("re-declaring answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "triager", targets, &plan)
		found = ""
		for _, one := range plan.Items {
			if one.Elsewhere != "" {
				found = one.Elsewhere
			}
		}
		if found == "" {
			t.Errorf("re-sending the plan erased where the work is: %+v", plan.Items)
		}

		// And sent empty it is cleared, because a stale link is worse than
		// none.
		if got := asPerson(t, r, "triager", http.MethodPut, targets,
			`{"builds":[{"stream":"master","variant":"broadcom","elsewhere":""}]}`,
		); got.Code != http.StatusOK {
			t.Fatalf("clearing answered %d: %s", got.Code, got.Body.String())
		}
		// Decoded into a fresh value rather than into the one above: a field
		// left out of the answer — which is what an emptied link looks like —
		// keeps whatever the last decode put there, and the test would then
		// be asserting against its own memory.
		var after struct {
			Items []struct {
				Stream    string `json:"stream"`
				Elsewhere string `json:"elsewhere"`
			} `json:"items"`
		}
		read(t, r, "triager", targets, &after)
		for _, one := range after.Items {
			if one.Elsewhere != "" {
				t.Errorf("an emptied link is still recorded: %+v", one)
			}
		}
	})
}
