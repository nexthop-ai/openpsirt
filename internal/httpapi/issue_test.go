package httpapi_test

import (
	"net/http"
	"testing"
)

func TestOneIssueIsAnsweredAcrossEveryProductYouMaySee(t *testing.T) {
	// "A critical just landed in openssl — which of our products ship an
	// affected version" was a question asked one product at a time, which
	// at a dozen products is the first thing anybody complains about.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		var out struct {
			Vulnerability string `json:"vulnerability"`
			Products      int    `json:"products"`
			Total         int    `json:"total"`
			Items         []struct {
				Product   string `json:"product"`
				Stream    string `json:"stream"`
				Variant   string `json:"variant"`
				Component string `json:"component"`
				Places    int    `json:"places"`
				State     string `json:"state"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/issues/CVE-2026-9999", &out)
		if len(out.Items) == 0 || out.Products != 1 {
			t.Fatalf("the issue reads as %+v", out)
		}
		one := out.Items[0]
		if one.Product != "mine" || one.Component != "libnl-3-200" || one.Places < 1 {
			t.Errorf("the row reads as %+v", one)
		}
		if one.State != "undecided" {
			t.Errorf("a finding nobody has decided reads as %q", one.State)
		}

		// Deciding it moves the state on this page too: it is the same
		// definition the findings list uses rather than a second one.
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		read(t, r, "triager", "/v1/issues/CVE-2026-9999", &out)
		if out.Items[0].State != "waiting" {
			t.Errorf("a claim nobody has agreed to reads as %q", out.Items[0].State)
		}
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			"/v1/claims/"+itoa(claim)+"/approval", `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "triager", "/v1/issues/CVE-2026-9999", &out)
		if out.Items[0].State != "agreed" {
			t.Errorf("an approved claim reads as %q", out.Items[0].State)
		}

		// Somebody who reads a different product is told the same thing as
		// somebody asking about an issue that does not exist: an issue
		// existing somewhere they hold nothing is not ours to confirm. (A
		// subject granted nothing at all is refused before this, at the door.)
		// Somebody granted only a capability reaches no product, so an issue
		// existing is not something they are told either — and it is the same
		// answer as an issue nobody has heard of, deliberately.
		if got := asPerson(t, r, "approver", http.MethodGet,
			"/v1/issues/CVE-2026-9999", ""); got.Code != http.StatusNotFound {
			t.Errorf("somebody who reaches no product was told it exists: %d", got.Code)
		}
		if got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/issues/CVE-1999-0001", ""); got.Code != http.StatusNotFound {
			t.Errorf("an issue nobody has heard of answered %d", got.Code)
		}
	})
}
