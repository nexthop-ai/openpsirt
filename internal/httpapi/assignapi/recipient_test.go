// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

const disclosedAt = "/v1/products/mine/branches-and-tags/master/variants/broadcom" +
	"/findings/CVE-2026-9999/components/libnl-3-200/assignment"

// heldTotal is how many pieces of work somebody holds, read as them.
func heldTotal(t *testing.T, r *httpapitest.Reach, who string) int {
	t.Helper()
	var mine struct {
		Total int `json:"total"`
	}
	httpapitest.Read(t, r, who, "/v1/people/me/assignments", &mine)
	return mine.Total
}

// Disclosed work is handed only to somebody who holds a role in its product
// and has not left. Handed to anybody else, it names the product, its
// releases and the issue to somebody the product is meant to read as not
// existing for, or sits with somebody refused at sign-in.
func TestDisclosedWorkIsGivenOnlyToSomebodyHoldingARoleInItsProduct(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)

		// "outsider" holds a role on the other product only.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "assigner", http.MethodPut, disclosedAt,
			`{"person":"outsider"}`), http.StatusUnprocessableEntity)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/findings/assignment", `{"person":"outsider"}`),
			http.StatusUnprocessableEntity)
		if held := heldTotal(t, r, "outsider"); held != 0 {
			t.Errorf("somebody holding nothing on the product was handed %d pieces of its work", held)
		}

		// Somebody who has left holds nothing anywhere.
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/people/reader/deactivation", ""); got.Code != http.StatusOK {
			t.Fatalf("deactivating answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "assigner", http.MethodPut, disclosedAt,
			`{"person":"reader"}`), http.StatusUnprocessableEntity)

		// Somebody holding a role in the product is handed it.
		if got := httpapitest.AsPerson(t, r, "assigner", http.MethodPut, disclosedAt,
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("handing disclosed work to a triager answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// Moving everything one person holds asks the recipient about every product
// the work is in, disclosed work included.
func TestHandingSomebodysWorkOverAsksTheRecipientAboutEveryProduct(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPut, disclosedAt,
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("taking the work answered %d: %s", got.Code, got.Body.String())
		}
		const handOver = "/v1/people/triager/assignments/hand-back"
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "admin", http.MethodPost, handOver,
			`{"to":"outsider"}`), http.StatusUnprocessableEntity)
		if held := heldTotal(t, r, "outsider"); held != 0 {
			t.Errorf("somebody holding nothing on the product was handed %d pieces of its work", held)
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/people/reader/deactivation", ""); got.Code != http.StatusOK {
			t.Fatalf("deactivating answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "admin", http.MethodPost, handOver,
			`{"to":"reader"}`), http.StatusUnprocessableEntity)
		if held := heldTotal(t, r, "triager"); held != 1 {
			t.Errorf("a refused hand-over left the holder %d pieces of work, want the one they took", held)
		}

		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, handOver,
			`{"to":"assigner"}`); got.Code != http.StatusOK {
			t.Fatalf("handing work to somebody holding a role answered %d: %s", got.Code, got.Body.String())
		}
		if held := heldTotal(t, r, "assigner"); held != 1 {
			t.Errorf("the recipient holds %d pieces of work, want the one handed over", held)
		}
	})
}

// Planning an upgrade asks for triage before it resolves who carries it, so a
// caller who may not triage is answered the same for a name somebody holds and
// a name nobody does.
func TestPlanningAnUpgradeSaysNothingAboutWhoHasAnAccount(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		plan := func(person string) (int, string) {
			got := httpapitest.AsPerson(t, r, "dispatcher", http.MethodPost,
				"/v1/products/mine/components/libcurl4t64/upgrade",
				`{"to":"8.5.0-1","by":"`+httpapitest.AheadOfUs+`",`+
					`"reasoning":"Taking the 8.5.0 bump in the next build.",`+
					`"person":"`+person+`",`+
					`"builds":[{"branch_or_tag":"master","variant":"broadcom"}]}`)
			return got.Code, got.Body.String()
		}
		heldCode, heldBody := plan("triager")
		unheldCode, unheldBody := plan("nobody-has-this-name")
		if heldCode != http.StatusForbidden {
			t.Errorf("somebody who may not triage was answered %d: %s", heldCode, heldBody)
		}
		if heldCode != unheldCode || heldBody != unheldBody {
			t.Errorf("a name somebody holds answers %d %s and a name nobody holds %d %s",
				heldCode, heldBody, unheldCode, unheldBody)
		}
	})
}

// Handing a planned upgrade to somebody else is authorized before any build in
// the body is resolved, so a build name the caller got wrong and one they got
// right are refused alike.
func TestPlanningAnUpgradeForSomebodyElseIsAuthorizedBeforeItsBuildsAreRead(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		plan := func(branch string) (int, string) {
			got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
				"/v1/products/mine/components/libcurl4t64/upgrade",
				`{"to":"8.5.0-1","by":"`+httpapitest.AheadOfUs+`",`+
					`"reasoning":"Taking the 8.5.0 bump in the next build.",`+
					`"person":"assigner",`+
					`"builds":[{"branch_or_tag":"`+branch+`","variant":"broadcom"}]}`)
			return got.Code, got.Body.String()
		}
		realCode, realBody := plan("master")
		wrongCode, wrongBody := plan("no-such-branch")
		if realCode != http.StatusUnprocessableEntity {
			t.Errorf("a triager giving work away was answered %d: %s", realCode, realBody)
		}
		if realCode != wrongCode || realBody != wrongBody {
			t.Errorf("a build that exists answers %d %s and one that does not %d %s",
				realCode, realBody, wrongCode, wrongBody)
		}
	})
}
