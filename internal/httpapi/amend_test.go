package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRenamingAVariantIsRefusedOnceADocumentHasGoneOut pins the rule the whole
// rename rests on.
//
// A published document is identified by the build it describes, and the name
// is inside that identifier. Renamed afterwards, the next document carries a
// different identifier — which a reader holding the first reads as a second
// document rather than as a revision of theirs — and the record of what went
// out carries the build and the revision number, never a name, so nothing
// there can be corrected to match.
func TestRenamingAVariantIsRefusedOnceADocumentHasGoneOut(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		const variant = "/v1/products/mine/variants/broadcom"

		// Before anything goes out, the name is still ours to correct.
		if got := asPerson(t, r, "admin", http.MethodPatch, variant,
			`{"name":"broadcom-dnx"}`); got.Code != http.StatusNoContent {
			t.Fatalf("renaming before publication answered %d: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "admin", http.MethodPatch,
			"/v1/products/mine/variants/broadcom-dnx",
			`{"name":"broadcom"}`); got.Code != http.StatusNoContent {
			t.Fatalf("renaming it back answered %d: %s", got.Code, got.Body.String())
		}

		recordedIssuance(t, r, "triager")

		got := asPerson(t, r, "admin", http.MethodPatch, variant, `{"name":"broadcom-dnx"}`)
		if got.Code != http.StatusConflict {
			t.Fatalf("renaming after publication answered %d: %s", got.Code, got.Body.String())
		}
		if !strings.Contains(got.Body.String(), "published") {
			t.Errorf("the refusal does not say why: %s", got.Body.String())
		}

		// What it reaches is not the name and is not in any document, so it
		// stays correctable.
		if got := asPerson(t, r, "admin", http.MethodPatch, variant,
			`{"customer_facing":false}`); got.Code != http.StatusNoContent {
			t.Errorf("correcting what it reaches answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// TestARetiredVariantTakesNoScan pins the other half of retiring one.
//
// The lists stop offering it, and this stops a pipeline still configured for
// it filing against it anyway. The refusal says what to do, because what has
// to change is a build script somebody maintains.
func TestARetiredVariantTakesNoScan(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		if got := asPerson(t, r, "admin", http.MethodDelete,
			"/v1/products/mine/variants/broadcom", ""); got.Code != http.StatusNoContent {
			t.Fatalf("retiring answered %d: %s", got.Code, got.Body.String())
		}

		// Sent through the endpoint a build sends to, because the refusal is
		// what that endpoint does: a store write would not reach it.
		//
		// What it says is the assertion rather than the status. A build
		// already stands here, so every date this could carry is refused for
		// a reason of its own — older than what is filed, or ahead of the
		// clock — and a check on the status alone passes with the refusal
		// taken out.
		req := upload(t, "/v1/products/mine/streams/master/variants/broadcom/scans",
			inventory(nowish(), "libc6"))
		fromOurOwnPage(req)
		req.Header.Set(testHeader, "triager")
		refused := httptest.NewRecorder()
		r.handler.ServeHTTP(refused, req)
		said := refused.Body.String()
		if !strings.Contains(said, "retired") || !strings.Contains(said, "declare it again") {
			t.Fatalf("a scan of a retired variant answered %d: %s", refused.Code, said)
		}
		if refused.Code != http.StatusConflict {
			t.Errorf("it was refused with %d", refused.Code)
		}

		// What was already filed against it is still there. Retiring hides a
		// variant; it strands nothing.
		var open struct {
			Items []struct {
				Identifier string `json:"identifier"`
			} `json:"items"`
		}
		read(t, r, "triager",
			"/v1/findings?product=mine&stream=master&variant=broadcom", &open)
		if len(open.Items) == 0 {
			t.Error("retiring a variant took its findings with it")
		}

		// Gone from what the product declares, which is the list every picker
		// offers from, and still named by what the release was built as —
		// where the findings above sit.
		var declares, built struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/products/mine/variants", &declares)
		for _, item := range declares.Items {
			if item.Name == "broadcom" {
				t.Error("a retired variant is still offered as a way the product is built")
			}
		}
		read(t, r, "admin", "/v1/products/mine/streams/master/variants", &built)
		named := false
		for _, item := range built.Items {
			named = named || item.Name == "broadcom"
		}
		if !named {
			t.Error("the release stopped naming what it was built as")
		}
	})
}

// TestOnlyAnAdministratorAmendsAVariant pins who reaches the two writes.
//
// A variant decides what a scan may name, what every picker offers and how a
// finding ranks. Triage is not administration, and the two are separate for
// that reason.
func TestOnlyAnAdministratorAmendsAVariant(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const variant = "/v1/products/mine/variants/broadcom"

		for _, who := range []string{"triager", "reader"} {
			if got := asPerson(t, r, who, http.MethodPatch, variant,
				`{"name":"broadcom-dnx"}`); got.Code != http.StatusForbidden {
				t.Errorf("%s renaming a variant answered %d: %s",
					who, got.Code, got.Body.String())
			}
			if got := asPerson(t, r, who, http.MethodDelete, variant,
				""); got.Code != http.StatusForbidden {
				t.Errorf("%s retiring a variant answered %d: %s",
					who, got.Code, got.Body.String())
			}
		}
	})
}

// TestAmendingAVariantSaysWhatToChange pins that an empty request is refused
// rather than answered as done.
//
// Both fields are left alone where the request omits them, so a request
// omitting both asks for nothing and reporting success would say something
// happened.
func TestAmendingAVariantSaysWhatToChange(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		got := asPerson(t, r, "admin", http.MethodPatch,
			"/v1/products/mine/variants/broadcom", `{}`)
		if got.Code != http.StatusBadRequest {
			t.Fatalf("a request naming nothing answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// TestRetiringAVariantTwiceIsRefused pins that the second administrator is
// told so rather than recording having done it.
func TestRetiringAVariantTwiceIsRefused(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const variant = "/v1/products/mine/variants/broadcom"
		if got := asPerson(t, r, "admin", http.MethodDelete, variant, ""); got.Code != http.StatusNoContent {
			t.Fatalf("retiring answered %d: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "admin", http.MethodDelete, variant, ""); got.Code != http.StatusConflict {
			t.Errorf("retiring a retired variant answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// TestRenamingIsRefusedOnceAnAdvisoryHasGoneOut pins the half of the rule that
// a VEX document does not cover.
//
// A published advisory names each affected release in its product tree by the
// build it is, so a product or a release renamed afterwards is named
// differently in the next revision — and a reader matching the identifier they
// hold finds it absent, which reads as no longer affected about a customer who
// still is.
func TestRenamingIsRefusedOnceAnAdvisoryHasGoneOut(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		// Correctable while nothing has gone out.
		if got := asPerson(t, r, "admin", http.MethodPatch, "/v1/products/mine",
			`{"name":"ours"}`); got.Code != http.StatusNoContent {
			t.Fatalf("renaming a product before publication answered %d: %s",
				got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "admin", http.MethodPatch, "/v1/products/ours",
			`{"name":"mine"}`); got.Code != http.StatusNoContent {
			t.Fatalf("renaming it back answered %d: %s", got.Code, got.Body.String())
		}

		// A flaw of our own, on an advisory, agreed to and published.
		made := asPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+
				`"summary":"The management socket answers before anyone authenticated.",`+
				`"severity":"critical"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording a flaw answered %d: %s", made.Code, made.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		at := "/v1/advisories/" + advisoryOver(t, r, "private-triage", "mine", recorded.Identifier)
		agreedTo(t, r, at)
		if issued := asPerson(t, r, "private-triage", http.MethodPost, at+"/issuance",
			`{"summary":"First advisory."}`); issued.Code != http.StatusCreated {
			t.Fatalf("publishing answered %d: %s", issued.Code, issued.Body.String())
		}

		// The product and the release it named are now held by readers.
		for _, refused := range []struct {
			what string
			at   string
			body string
		}{
			{"the product", "/v1/products/mine", `{"name":"ours"}`},
			{"the release", "/v1/products/mine/streams/master", `{"name":"main"}`},
		} {
			// Fatal rather than an error: a rename that went through leaves
			// the world under a different name, and every check after it
			// fails for that instead of for its own reason.
			got := asPerson(t, r, "admin", http.MethodPatch, refused.at, refused.body)
			if got.Code != http.StatusConflict {
				t.Fatalf("renaming %s after publication answered %d: %s",
					refused.what, got.Code, got.Body.String())
			}
			if !strings.Contains(got.Body.String(), "published") {
				t.Errorf("renaming %s refuses without saying why: %s",
					refused.what, got.Body.String())
			}
		}

		// The displayed name is in no identifier, so it stays correctable.
		if got := asPerson(t, r, "admin", http.MethodPatch, "/v1/products/mine",
			`{"display_name":"Ours, Renamed"}`); got.Code != http.StatusNoContent {
			t.Errorf("correcting the displayed name answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}

// TestARetiredProductOrReleaseTakesNoScan pins that the refusal names which
// level is retired, in the spelling the sender sent.
func TestARetiredProductOrReleaseTakesNoScan(t *testing.T) {
	for _, level := range []struct {
		name  string
		at    string
		says  string
		named string
	}{
		{"release", "/v1/products/mine/streams/master", "release", "master"},
		{"product", "/v1/products/mine", "product", "mine"},
	} {
		t.Run(level.name, func(t *testing.T) {
			eachReach(t, func(t *testing.T, r *reach) {
				r.scannedWithEvidence(t)
				if got := asPerson(t, r, "admin", http.MethodDelete, level.at,
					""); got.Code != http.StatusNoContent {
					t.Fatalf("retiring the %s answered %d: %s",
						level.name, got.Code, got.Body.String())
				}

				req := upload(t, "/v1/products/mine/streams/master/variants/broadcom/scans",
					inventory(nowish(), "libc6"))
				fromOurOwnPage(req)
				req.Header.Set(testHeader, "triager")
				refused := httptest.NewRecorder()
				r.handler.ServeHTTP(refused, req)
				said := refused.Body.String()
				// What it says rather than the status, for the reason the
				// variant's test gives: a build already stands here, so every
				// date this could carry is refused for a reason of its own.
				// The name is quoted in the message and the message is inside
				// JSON, so the quotes arrive escaped.
				wanted := level.says + ` \"` + level.named + `\"`
				if !strings.Contains(said, wanted) || !strings.Contains(said, "retired") {
					t.Fatalf("a scan of a retired %s answered %d: %s",
						level.name, refused.Code, said)
				}
			})
		})
	}
}

// TestOnlyAnAdministratorAmendsAProductOrRelease pins who reaches the four
// writes a level above a variant.
func TestOnlyAnAdministratorAmendsAProductOrRelease(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		for _, at := range []string{"/v1/products/mine", "/v1/products/mine/streams/master"} {
			for _, who := range []string{"triager", "reader"} {
				if got := asPerson(t, r, who, http.MethodPatch, at,
					`{"name":"other"}`); got.Code != http.StatusForbidden {
					t.Errorf("%s renaming %s answered %d: %s", who, at, got.Code, got.Body.String())
				}
				if got := asPerson(t, r, who, http.MethodDelete, at,
					""); got.Code != http.StatusForbidden {
					t.Errorf("%s retiring %s answered %d: %s", who, at, got.Code, got.Body.String())
				}
			}
		}
	})
}
