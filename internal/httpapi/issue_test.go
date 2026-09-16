package httpapi_test

import (
	"encoding/json"
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

		// Nothing affected is an answer, and it is the one a customer inquiry
		// asks for: "are you affected by this" could be answered yes and
		// never no.
		//
		// And the two ways of not being affected answer identically. Somebody
		// who reaches no product, and somebody asking about an identifier
		// nobody here has seen, are told the same thing — told apart, the
		// pair says which issues this deployment holds, one guess at a time,
		// about products somebody may not read. (A subject granted nothing at
		// all is refused before this, at the door.)
		unaffected := func(t *testing.T, who, at string) {
			t.Helper()
			got := asPerson(t, r, who, http.MethodGet, at, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s asking %s answered %d", who, at, got.Code)
			}
			var said struct {
				Vulnerability string `json:"vulnerability"`
				Description   string `json:"description"`
				Severity      string `json:"severity"`
				Items         []struct {
					Product string `json:"product"`
				} `json:"items"`
				Total int `json:"total"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &said); err != nil {
				t.Fatal(err)
			}
			if said.Total != 0 || len(said.Items) != 0 {
				t.Errorf("%s asking %s was told about %d rows", who, at, said.Total)
			}
			// And nothing about the issue itself, which is what would tell
			// the two cases apart.
			if said.Description != "" || said.Severity != "" {
				t.Errorf("%s asking %s was told what the issue is: %+v", who, at, said)
			}
		}
		unaffected(t, "approver", "/v1/issues/CVE-2026-9999")
		unaffected(t, "triager", "/v1/issues/CVE-1999-0001")
	})
}
