package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// One person brought into one undisclosed case, without being granted private
// reading on the product.
//
// The case it exists for is the engineer who normally sees only public
// findings and is needed on one embargoed flaw in their own component — so
// what is tested is both halves: that they can reach the one issue, and that
// reaching it gives them nothing else of the product.
func TestSomebodyIsBroughtIntoOneCaseAndReachesNothingElse(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		embargoed := r.embargoed(t)

		const collaborators = "/v1/products/mine/issues/%s/collaborators/%s"

		// Before anything, the person who reads only public work cannot see
		// the embargoed finding at all.
		before := asPerson(t, r, "triager", http.MethodGet, findingAt(embargoed), "")
		if before.Code != http.StatusNotFound {
			t.Fatalf("an embargoed finding answered %d to somebody who may not read one",
				before.Code)
		}

		// Somebody who may not read undisclosed work here cannot bring anybody
		// in: managing the list is knowing the case.
		if got := asPerson(t, r, "triager", http.MethodPut,
			fmt.Sprintf(collaborators, embargoed, "reader"), ""); got.Code != http.StatusNotFound {
			t.Errorf("somebody who cannot read the case managed its list: %d", got.Code)
		}

		// Whoever reads the case brings them in.
		if got := asPerson(t, r, "private-triage", http.MethodPut,
			fmt.Sprintf(collaborators, embargoed, "triager"),
			""); got.Code != http.StatusNoContent {
			t.Fatalf("bringing somebody in answered %d: %s", got.Code, got.Body.String())
		}

		// Now they read that one finding.
		after := asPerson(t, r, "triager", http.MethodGet, findingAt(embargoed), "")
		if after.Code != http.StatusOK {
			t.Fatalf("a collaborator cannot read the case they are on: %d %s",
				after.Code, after.Body.String())
		}

		// And nothing else of the product. The other embargoed finding is not
		// theirs, and the product's list of undisclosed work is not either.
		var listed struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Undisclosed   bool   `json:"undisclosed"`
			} `json:"items"`
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings", &listed)
		for _, row := range listed.Items {
			if row.Undisclosed {
				t.Errorf("the case appears in a collaborator's findings list: %+v", row)
			}
		}

		// They may argue about it: a collaborator proposes and comments.
		decide := "/v1/products/mine/streams/master/variants/broadcom/findings/" +
			embargoed + "/components/libnl-3-200/decision"
		made := asPerson(t, r, "triager", http.MethodPost, decide, dismissal)
		if made.Code != http.StatusCreated {
			t.Fatalf("a collaborator could not argue about the case: %d %s",
				made.Code, made.Body.String())
		}
		var claim struct {
			ClaimID int64   `json:"claim_id"`
			IDs     []int64 `json:"ids"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &claim); err != nil {
			t.Fatal(err)
		}

		// And may not agree to one. Two collaborators could otherwise satisfy
		// the two people a dismissal asks for with nobody accountable for the
		// product involved.
		if got := asPerson(t, r, "private-triage", http.MethodPut,
			fmt.Sprintf(collaborators, embargoed, "reader"),
			""); got.Code != http.StatusNoContent {
			t.Fatalf("bringing a second person in answered %d", got.Code)
		}
		if got := asPerson(t, r, "reader", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim.ClaimID), `{}`); got.Code < 400 {
			t.Errorf("a collaborator agreed to a claim on the case: %d %s",
				got.Code, got.Body.String())
		}

		// Being brought in is said at once, and says which issue: this is the
		// one message that names an undisclosed finding on purpose, and it
		// goes to the person who has just been granted it.
		told := r.told(t, "triager", "brought-in")
		if len(told) != 1 || !contains(told[0], embargoed) {
			t.Errorf("being brought into a case was said as %v", told)
		}

		// It is an access change and lands in the trail.
		var trail struct {
			Items []struct {
				Kind  string `json:"kind"`
				About string `json:"about"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/administration/changes?kind=case", &trail)
		if len(trail.Items) == 0 || !contains(trail.Items[0].About, embargoed) {
			t.Errorf("bringing somebody into a case is not in the trail: %+v", trail.Items)
		}

		// Taken off, they lose it again — and the record of it is kept.
		if got := asPerson(t, r, "private-triage", http.MethodDelete,
			fmt.Sprintf(collaborators, embargoed, "triager"),
			""); got.Code != http.StatusNoContent {
			t.Fatalf("taking somebody off answered %d: %s", got.Code, got.Body.String())
		}
		if gone := asPerson(t, r, "triager", http.MethodGet,
			findingAt(embargoed), ""); gone.Code != http.StatusNotFound {
			t.Errorf("somebody taken off a case still reads it: %d", gone.Code)
		}
		read(t, r, "admin", "/v1/administration/changes?kind=case", &trail)
		if len(trail.Items) < 2 {
			t.Errorf("withdrawing the grant is not in the trail: %+v", trail.Items)
		}
	})
}

// embargoed records a flaw nobody has announced and returns its identifier.
func (r *reach) embargoed(t *testing.T) string {
	t.Helper()
	got := asPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/findings",
		`{"builds":[{"stream":"master","variant":"broadcom"}],`+
			`"summary":"The management socket answers before anyone has authenticated.",`+
			`"severity":"high","component":"libnl-3-200"}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("recording a flaw answered %d: %s", got.Code, got.Body.String())
	}
	var recorded struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	return recorded.Identifier
}

// findingAt is where one issue in the scanned build is read.
func findingAt(vulnerability string) string {
	return "/v1/products/mine/streams/master/variants/broadcom/findings/" +
		vulnerability + "/components/libnl-3-200"
}

func TestACollaboratorReadsTheDecisionsTheirCaseIsListedWith(t *testing.T) {
	// The grant is the pair of a product and an issue, and the list
	// narrowing asks it — so a collaborator's own case appeared among the
	// decisions and every route reading one of them by identifier refused
	// it. Listed and then not there reads as a fault rather than as a
	// rule, and a grant whose rows cannot be opened is a grant with no
	// content.
	//
	// Arguing and agreeing are unchanged: a collaborator may argue about
	// the issue they were brought in on and may not agree to anybody's
	// claim about it.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		embargoed := r.embargoed(t)

		if got := asPerson(t, r, "private-triage", http.MethodPut,
			fmt.Sprintf("/v1/products/mine/issues/%s/collaborators/%s", embargoed, "triager"),
			""); got.Code != http.StatusNoContent {
			t.Fatalf("bringing somebody into the case answered %d: %s",
				got.Code, got.Body.String())
		}

		// The person who reads the case makes the claim, so what is being
		// measured is reading somebody else's decision rather than their own.
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom/findings/"+
				embargoed+"/components/libnl-3-200/decision", dismissal)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", made.Code, made.Body.String())
		}
		var claim struct {
			IDs []int64 `json:"ids"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &claim); err != nil {
			t.Fatal(err)
		}

		var listed struct {
			Items []struct {
				Decision struct {
					ID int64 `json:"id"`
				} `json:"decision"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/decisions", &listed)
		var found bool
		for _, one := range listed.Items {
			if one.Decision.ID == claim.IDs[0] {
				found = true
			}
		}
		if !found {
			t.Fatalf("the collaborator's own case is not in the list, so this proves nothing")
		}

		at := fmt.Sprintf("/v1/decisions/%d", claim.IDs[0])
		if got := asPerson(t, r, "triager", http.MethodGet, at, ""); got.Code != http.StatusOK {
			t.Errorf("a decision listed to this collaborator answered %d when opened: %s",
				got.Code, got.Body.String())
		}
	})
}
