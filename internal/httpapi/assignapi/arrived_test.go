// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestARulePlacesAFlawRecordedAfterTheRuleWasWritten(t *testing.T) {
	// A flaw somebody records, and a build added to one, open work as a scan
	// does, and a standing rule places it the same way.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		r.SiblingsAlsoIn(t, "marvell")
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		if made := httpapitest.AsPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/assignment-rules",
			`{"name":"curl to the curlers","team":"curlers","upstream":"curl"}`,
		); made.Code != http.StatusCreated {
			t.Fatalf("adding a rule answered %d: %s", made.Code, made.Body.String())
		}
		if placed := r.Swept(t); placed == 0 {
			t.Fatal("the rule's own sweep placed nothing")
		}

		recorded := httpapitest.AsPerson(t, r, "triager", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],`+
				`"summary":"The transfer handle is freed twice on a redirect.",`+
				`"severity":"high","component":"libcurl4t64","disclosed":true}`)
		if recorded.Code != http.StatusCreated {
			t.Fatalf("recording a flaw answered %d: %s", recorded.Code, recorded.Body.String())
		}
		var flaw struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(recorded.Body.Bytes(), &flaw); err != nil {
			t.Fatal(err)
		}
		if placed := r.Swept(t); placed == 0 {
			t.Fatal("nothing was placed after a flaw was recorded beneath the rule")
		}
		placedBy(t, r, "triager", "broadcom", flaw.Identifier, "libcurl4t64", "curl to the curlers")

		widened := httpapitest.AsPerson(t, r, "triager", http.MethodPut,
			"/v1/products/mine/issues/"+flaw.Identifier+"/builds",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"},`+
				`{"branch_or_tag":"master","variant":"marvell"}]}`)
		if widened.Code != http.StatusOK {
			t.Fatalf("widening the flaw answered %d: %s", widened.Code, widened.Body.String())
		}
		if placed := r.Swept(t); placed == 0 {
			t.Fatal("nothing was placed after a flaw was widened to a build beneath the rule")
		}
		placedBy(t, r, "triager", "marvell", flaw.Identifier, "libcurl4t64", "curl to the curlers")
	})
}

func TestARulePlacesAFlawRecordedFromACodeFinding(t *testing.T) {
	// Recording a confirmed code finding as a flaw opens work through the
	// path every recorded flaw takes, and a standing rule places it.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"builders","members":["private-triage"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		if made := httpapitest.AsPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/assignment-rules",
			`{"name":"the build to the builders","team":"builders","beneath":"mine-broadcom"}`,
		); made.Code != http.StatusCreated {
			t.Fatalf("adding a rule answered %d: %s", made.Code, made.Body.String())
		}
		r.Swept(t)

		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence
		if got := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, at+"/decision",
			`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`); got.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", got.Code, got.Body.String())
		}
		recorded := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, at+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"p leaks on the early return"}`)
		if recorded.Code != http.StatusCreated {
			t.Fatalf("recording the code finding as a flaw answered %d: %s", recorded.Code, recorded.Body.String())
		}
		var flaw struct {
			Identifier string `json:"identifier"`
			Component  string `json:"component"`
		}
		if err := json.Unmarshal(recorded.Body.Bytes(), &flaw); err != nil {
			t.Fatal(err)
		}
		if placed := r.Swept(t); placed == 0 {
			t.Fatal("nothing was placed after a code finding was recorded as a flaw beneath the rule")
		}
		placedBy(t, r, "private-triage", "broadcom", flaw.Identifier, flaw.Component, "the build to the builders")
	})
}

// placedBy fails unless the flaw's finding on a component in this variant, as
// one person reads it, names the rule that placed it.
func placedBy(t *testing.T, r *httpapitest.Reach, reader, variant, issue, component, rule string) {
	t.Helper()
	var detail struct {
		AssignedByRule string `json:"assigned_by_rule"`
	}
	httpapitest.Read(t, r, reader, "/v1/products/mine/branches-and-tags/master/variants/"+variant+
		"/findings/"+issue+"/components/"+component, &detail)
	if detail.AssignedByRule != rule {
		t.Errorf("the flaw in %s says %q placed it, want %q", variant, detail.AssignedByRule, rule)
	}
}
