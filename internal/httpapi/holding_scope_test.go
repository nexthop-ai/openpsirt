package httpapi_test

import (
	"net/http"
	"testing"
)

// Somebody who reads nothing can still read their own work in the build it is
// in.
//
// a capability held without a read role reaches no product, and what gives it
// content is what has been assigned. The store answers for exactly that — and
// the endpoint refused first, because narrowing to a build asked whether the
// caller may *read* the product. So the screen that shows an approver what
// they are dealing with told them the product does not exist, while the tree
// beside it, which had this right, drew their work.
//
// What the refusal was protecting is kept: nothing of theirs in a product they
// cannot read still answers as a product that was never declared, so this
// cannot be used to find out which products exist.
func TestWhatSomebodyHoldsIsReadableInABuildTheyCannotRead(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		// The approver in this cast holds the capability and no reading, which
		// is the identity the rule is about.
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		if got := asPerson(t, r, "assigner", http.MethodPut, at,
			`{"person":"approver"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}

		// Unscoped, which always worked.
		var everywhere struct {
			Total int `json:"total"`
		}
		read(t, r, "approver", "/v1/people/me/assignments", &everywhere)
		if everywhere.Total != 1 {
			t.Fatalf("they hold %d without a scope, want the one", everywhere.Total)
		}

		// And narrowed to the build it is in, which is what the screen asks.
		var here struct {
			Total int `json:"total"`
		}
		read(t, r, "approver", "/v1/people/me/assignments"+
			"?product=mine&stream=master&variant=broadcom", &here)
		if here.Total != 1 {
			t.Errorf("narrowed to the build they hold it in, they hold %d", here.Total)
		}

		// A product they hold nothing in answers as one that does not exist,
		// whether or not it does.
		if refused := asPerson(t, r, "approver", http.MethodGet,
			"/v1/people/me/assignments?product=theirs", ""); refused.Code != http.StatusNotFound {
			t.Errorf("a product they hold nothing in answered %d: %s",
				refused.Code, refused.Body.String())
		}
		if refused := asPerson(t, r, "approver", http.MethodGet,
			"/v1/people/me/assignments?product=nosuchproduct",
			""); refused.Code != http.StatusNotFound {
			t.Errorf("a product that does not exist answered %d, so the two differ",
				refused.Code)
		}
	})
}
