package httpapi_test

import (
	"net/http"
	"testing"
)

func TestACapabilityWithNoReadRoleSeesWhatItWasAssigned(t *testing.T) {
	// An approver holding no read role could decide and see nothing — a
	// capability with no content. An assignment is itself a grant of
	// visibility of what was assigned, which is what gives it any.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		// Before: they hold the capability and reach nothing.
		var before struct {
			Total int `json:"total"`
		}
		read(t, r, "approver", "/v1/people/me/assignments", &before)
		if before.Total != 0 {
			t.Fatalf("an approver holding no read role already sees %d", before.Total)
		}

		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		if got := asPerson(t, r, "assigner", http.MethodPut, at,
			`{"person":"approver"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning to an approver answered %d: %s", got.Code, got.Body.String())
		}

		var after struct {
			Total int `json:"total"`
			Items []struct {
				Vulnerability string `json:"vulnerability"`
			} `json:"items"`
		}
		read(t, r, "approver", "/v1/people/me/assignments", &after)
		if after.Total != 1 || len(after.Items) != 1 {
			t.Fatalf("after being assigned work they see %d of %d",
				len(after.Items), after.Total)
		}
		if after.Items[0].Vulnerability != "CVE-2026-9999" {
			t.Errorf("they were shown %q", after.Items[0].Vulnerability)
		}

		// And nothing else. The grant is of what was assigned, not of the
		// product it happens to sit in, which stays a product they may not
		// know exists.
		if got := asPerson(t, r, "approver", http.MethodGet,
			"/v1/products/mine/findings", ""); got.Code != http.StatusNotFound {
			t.Errorf("being assigned one finding opened the product's list: %d %s",
				got.Code, got.Body.String())
		}
	})
}
