// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A decision states whom its published statement holds for where it is told,
// and answers whom it holds for either way: the scope stated, or what the
// reason decides. A scope on a deferral is refused.
func TestADecisionSaysWhomItsPublishedStatementHoldsFor(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		at := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/%s/decision", place)

		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",`+
				`"scope":"portable","reasoning":"Never reached on any build of it."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording a stated scope answered %d: %s", got.Code, got.Body.String())
		}
		var made struct {
			ID       int64  `json:"id"`
			Scope    string `json:"scope"`
			HoldsFor string `json:"holds_for"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		if made.Scope != "portable" || made.HoldsFor != "portable" {
			t.Errorf("the decision answers scope %q holding for %q, want both portable",
				made.Scope, made.HoldsFor)
		}
		var detail struct {
			Decision struct {
				Scope    string `json:"scope"`
				HoldsFor string `json:"holds_for"`
			} `json:"decision"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", made.ID), &detail)
		if detail.Decision.Scope != "portable" || detail.Decision.HoldsFor != "portable" {
			t.Errorf("read back as scope %q holding for %q", detail.Decision.Scope, detail.Decision.HoldsFor)
		}

		other := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"deferred","deferred_until":"2099-01-01","scope":"portable",`+
				`"reasoning":"Next quarter."}`)
		if other.Code != http.StatusUnprocessableEntity ||
			!strings.Contains(other.Body.String(), "states nobody it holds for") {
			t.Errorf("a scope on a deferral answered %d: %s", other.Code, other.Body.String())
		}
	})
}
