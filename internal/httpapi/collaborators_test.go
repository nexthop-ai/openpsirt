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
		person, err := r.rights.Ensure(ctx, "ana", "Ana Ruiz", false)
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
				Identity string `json:"identity"`
				Name     string `json:"name"`
				AddedAt  string `json:"added_at"`
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
		// Not the zero time. A person the grant reports and the rows do not
		// used to come back dated 0001-01-01.
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
	// grant with no content" — DESIGN-access.md says so, about the three reads
	// by identifier that used to do exactly that. The finding detail was a
	// fourth, through the graph.
	//
	// graph.visibleIn asks Sees and Reads product-wide with no case arm, and
	// Detail calls Chains to build the way down to each place. So a
	// collaborator holding no role on the product was refused the path to the
	// component their own case sits in, and the route answered "no open
	// finding is recorded there".
	//
	// Every existing collaborator test passes because it uses an identity that
	// also holds a product role, which carries it through.
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
