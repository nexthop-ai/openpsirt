// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// decided is what one decision reports having written.
type decided struct {
	DecisionID int64 `json:"decision_id"`
	Recorded   int   `json:"recorded"`
	Also       []struct {
		Stream   string `json:"stream"`
		Variant  string `json:"variant"`
		Recorded int    `json:"recorded"`
	} `json:"also"`
}

func TestOneDecisionAcrossBuildsIsWrittenWholeOrNotAtAll(t *testing.T) {
	// Applied a build at a time, a decision half-applies: a refusal
	// part-way leaves it recorded in some releases and not others, as an
	// act nobody performed and nobody can point at afterwards.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		r.ScannedAlso(t, "mellanox", "3.8.0")

		const at = "/v1/products/mine/branches-and-tags/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/decision"

		// A build nobody scanned, named beside one somebody did.
		refused := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"wont-fix","reasoning":"Not worth it.",`+
				`"also":[{"stream":"master","variant":"nosuch"}]}`)
		if refused.Code != http.StatusNotFound {
			t.Fatalf("naming a build that is not there answered %d, want 404: %s",
				refused.Code, refused.Body.String())
		}

		// The whole point: the build that would have succeeded holds nothing.
		if state := r.StateOf(t, "broadcom"); state != "undecided" {
			t.Errorf("a refused decision left the first build %q, so it half-applied", state)
		}

		// And one decision across two builds that are both there covers
		// both.
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"wont-fix","reasoning":"Not worth it.",`+
				`"also":[{"stream":"master","variant":"mellanox","version":"3.8.0"}]}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding across two builds answered %d: %s", got.Code, got.Body.String())
		}
		var out decided
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if out.Recorded != 1 {
			t.Errorf("the build in the path recorded %d, want its one occurrence", out.Recorded)
		}
		if len(out.Also) != 1 || out.Also[0].Variant != "mellanox" || out.Also[0].Recorded != 1 {
			t.Fatalf("the other build reported %+v, want one occurrence in mellanox", out.Also)
		}
		// One action, one decision, so an approver agrees to the decision rather
		// than to one release of it.
		if out.DecisionID == 0 {
			t.Error("a decision across builds recorded nothing to agree to")
		}
		for _, variant := range []string{"broadcom", "mellanox"} {
			if state := r.StateOf(t, variant); state != "waiting" {
				t.Errorf("%s stands at %q after the decision, want waiting", variant, state)
			}
		}
	})
}

func TestABuildNamedTwiceInOneDecisionIsRefused(t *testing.T) {
	// One decision is recorded against a build once. Naming it twice is a
	// mistake that would otherwise be reported as a conflict from the write,
	// which says nothing about what the caller got wrong.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)

		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom"+
				"/findings/CVE-2026-9999/components/libnl-3-200/decision",
			`{"outcome":"wont-fix","reasoning":"Not worth it.",`+
				`"also":[{"stream":"master","variant":"broadcom"}]}`)
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("naming the same build twice answered %d, want 422: %s",
				got.Code, got.Body.String())
		}
	})
}
