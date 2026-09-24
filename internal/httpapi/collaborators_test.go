// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
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

func TestACollaboratorIsListedUnderTheNameThatTakesThemOff(t *testing.T) {
	// A grant on an embargoed case that the API can show and cannot withdraw.
	//
	// Store.Names answers a display name where one is set, and the list put
	// that in a field named identity. The removal route resolves {identity}
	// through ByIdentity, which matches the folded identity column — so
	// somebody with a display name was listed under a value matching no row,
	// the chip's remove answered 404, and the grant on the undisclosed issue
	// stood.
	//
	// Nothing could have caught it: every fixture in the tree sets a display
	// name equal to the identity, which is the one case where the two strings
	// agree.
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		r.scannedWithEvidence(t)
		embargoed := r.embargoed(t)

		// Somebody whose display name is not their identity, which is the
		// shape the recording route itself documents.
		person, err := r.rights.Ensure(ctx, "ana", "Ana Ruiz", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.rights.Claim(ctx, person.ID, "ana"); err != nil {
			t.Fatal(err)
		}
		mine, err := catalog.NewStore(r.db.DB).ProductByName(ctx, "mine")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.rights.GrantRole(ctx, person.ID, mine.ID, access.PublicRead); err != nil {
			t.Fatal(err)
		}

		at := "/v1/products/mine/issues/" + embargoed + "/collaborators"
		if got := asPerson(t, r, "private-triage", http.MethodPut,
			at+"/ana", ""); got.Code != http.StatusNoContent {
			t.Fatalf("bringing them in answered %d: %s", got.Code, got.Body.String())
		}

		var listed struct {
			Items []struct {
				Identity    string `json:"identity"`
				Name        string `json:"name"`
				AddedBy     string `json:"added_by"`
				AddedByName string `json:"added_by_name"`
				AddedAt     string `json:"added_at"`
			} `json:"items"`
		}
		read(t, r, "private-triage", at, &listed)
		if len(listed.Items) != 1 {
			t.Fatalf("the case lists %d collaborators: %+v", len(listed.Items), listed.Items)
		}
		one := listed.Items[0]
		// The handle in the field the removal route resolves, and the label
		// beside it rather than in place of it.
		if one.Identity != "ana" {
			t.Errorf("the collaborator is listed as %q, which resolves to nobody", one.Identity)
		}
		if one.Name != "Ana Ruiz" {
			t.Errorf("the listing does not say what to call them: %q", one.Name)
		}
		if one.AddedBy != "private-triage" || one.AddedByName != shownAs("private-triage") {
			t.Errorf("the listing names who brought them in as %q (%q), want the identity",
				one.AddedBy, one.AddedByName)
		}
		// Not the zero time. A person the grant reports and the rows do not
		// is left out rather than dated 0001-01-01.
		if strings.HasPrefix(one.AddedAt, "0001-") || one.AddedAt == "" {
			t.Errorf("the listing dates the grant %q", one.AddedAt)
		}

		// And what the list published takes them off again.
		// Escaped the way a client puts a path segment together, so that a
		// value which is not a handle fails the assertion above rather than
		// the request builder here.
		if got := asPerson(t, r, "private-triage", http.MethodDelete,
			at+"/"+url.PathEscape(one.Identity), ""); got.Code != http.StatusNoContent {
			t.Fatalf("removing them by the name the list gave answered %d: %s",
				got.Code, got.Body.String())
		}
		read(t, r, "private-triage", at, &listed)
		if len(listed.Items) != 0 {
			t.Errorf("they are still on the case: %+v", listed.Items)
		}
	})
}

func TestACollaboratorHoldingNothingHereOpensTheFindingTheirGrantIsFor(t *testing.T) {
	// "A grant that shows a row in a list and refuses it when opened is a
	// grant with no content" — DESIGN-access.md says so, about the reads by
	// identifier. The finding detail is a fourth, through the graph.
	//
	// graph.visibleIn asks Sees and Reads product-wide with no case arm, and
	// Detail calls Chains to build the way down to each place. A collaborator
	// holding no role on the product is then refused the path to the component
	// their own case sits in, and the route answers "no open finding is
	// recorded there".
	//
	// A collaborator test using an identity that also holds a product role
	// passes either way, carried through by the role.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		embargoed := r.embargoed(t)

		// Somebody with a role on the other product and nothing on this one,
		// which is what a collaborator brought in from outside looks like.
		if got := asPerson(t, r, "private-triage", http.MethodPut,
			"/v1/products/mine/issues/"+embargoed+"/collaborators/outsider",
			""); got.Code != http.StatusNoContent {
			t.Fatalf("bringing them in answered %d: %s", got.Code, got.Body.String())
		}

		var detail struct {
			Vulnerability string `json:"vulnerability"`
			Places        []struct {
				Place string `json:"place"`
				Down  []struct {
					Name string `json:"name"`
				} `json:"down"`
			} `json:"places"`
		}
		read(t, r, "outsider", findingAt(embargoed), &detail)
		if detail.Vulnerability != embargoed {
			t.Fatalf("the detail is about %q, want their case", detail.Vulnerability)
		}
		if len(detail.Places) == 0 {
			t.Error("the finding says it sits nowhere")
		}

		// And the case grant is still not a role on the product: the rest of
		// it stays out of reach.
		for _, path := range []string{
			"/v1/products/mine/findings",
			"/v1/products/mine/streams/master/variants/broadcom/vex",
		} {
			if got := asPerson(t, r, "outsider", http.MethodGet, path, ""); got.Code < 400 {
				t.Errorf("a case collaborator reached %s: %d", path, got.Code)
			}
		}
	})
}

func TestOneRequestGivesOneAnswerAboutWhatACollaboratorMaySee(t *testing.T) {
	// "May this subject see this product" has two rules here, and the pair is
	// deliberate: a route about the product as a whole asks what somebody may
	// see, and a route about one named issue admits somebody brought into a
	// case. Which of the two an endpoint wants is a security judgment, and
	// made by hand at every call site it is visible at none.
	//
	// Recording which builds an issue affects gates on the narrow rule and
	// then resolves each named build with the wide one, so one request gives
	// both answers about the same subject and the same product, four lines
	// apart.
	//
	// This pins the product question to one answer. What each route then
	// allows is a separate question, answered by the act: a
	// collaborator opens their case, and neither manages its list nor says
	// which builds the issue affects, because both are product-level acts.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		embargoed := r.embargoed(t)
		if got := asPerson(t, r, "private-triage", http.MethodPut,
			"/v1/products/mine/issues/"+embargoed+"/collaborators/outsider",
			""); got.Code != http.StatusNoContent {
			t.Fatalf("bringing them in answered %d: %s", got.Code, got.Body.String())
		}

		// The route about their own case answers it.
		if got := asPerson(t, r, "outsider", http.MethodGet,
			findingAt(embargoed), ""); got.Code != http.StatusOK {
			t.Fatalf("a route about their own case answered %d: %s",
				got.Code, got.Body.String())
		}

		// Every other issue-scoped route refuses them for what they may do,
		// never for the product not existing — that answer contradicts the one
		// they just got.
		const invisible = "no product is declared by that name"
		for _, c := range []struct {
			method string
			path   string
			body   string
		}{
			{http.MethodGet, "/v1/products/mine/issues/" + embargoed + "/collaborators", ""},
			{http.MethodPut, "/v1/products/mine/issues/" + embargoed + "/builds",
				`{"builds":[{"stream":"master","variant":"broadcom"}]}`},
		} {
			got := asPerson(t, r, "outsider", c.method, c.path, c.body)
			if got.Code < 400 {
				t.Errorf("%s %s answered %d for a case collaborator", c.method, c.path, got.Code)
			}
			if contains(got.Body.String(), invisible) {
				t.Errorf("%s %s says the product does not exist, having admitted them "+
					"to the same product elsewhere in the same breath: %s",
					c.method, c.path, got.Body.String())
			}
		}

		// And a route about the product as a whole is not theirs, which is
		// where that answer is the right one.
		got := asPerson(t, r, "outsider", http.MethodGet, "/v1/products/mine/assessments", "")
		if got.Code < 400 {
			t.Errorf("a case collaborator reached the product's assessments: %d", got.Code)
		}
	})
}

func TestWhatACollaboratorMayNotReachAnswersTheWayAStrangerIsAnswered(t *testing.T) {
	// A store refusal with no arm for it in the handler falls through to the
	// fault answer, so a route answered 500 where a stranger got 404. The
	// pair says the build is there, one name at a time — and the error text
	// names which of product, stream and variant was undeclared, which is the
	// list REQ-42 makes secret.
	//
	// A case collaborator is the reach that meets it: they hold nothing on
	// the product and may open exactly one finding, so every product-wide
	// read refuses them and each refusal has to look like the refusal a
	// stranger gets.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		embargoed := r.embargoed(t)
		if got := asPerson(t, r, "private-triage", http.MethodPut,
			"/v1/products/mine/issues/"+embargoed+"/collaborators/outsider",
			""); got.Code != http.StatusNoContent {
			t.Fatalf("bringing them in answered %d: %s", got.Code, got.Body.String())
		}

		build := "/v1/products/mine/streams/master/variants/broadcom"
		for _, path := range []string{
			build + "/scans",
			build + "/components",
			build + "/register",
			build + "/register.csv",
		} {
			collaborator := asPerson(t, r, "outsider", http.MethodGet, path, "")
			stranger := asPerson(t, r, "reader", http.MethodGet,
				"/v1/products/theirs/streams/master/variants/broadcom"+
					path[len(build):], "")
			if collaborator.Code != stranger.Code {
				t.Errorf("%s answers a collaborator %d and a stranger %d, so the pair "+
					"says which builds exist: %s",
					path, collaborator.Code, stranger.Code, collaborator.Body.String())
			}
			if collaborator.Code >= 500 {
				t.Errorf("%s answers a refusal as a fault: %d %s",
					path, collaborator.Code, collaborator.Body.String())
			}
		}
	})
}
