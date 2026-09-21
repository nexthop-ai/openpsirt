package httpapi_test

import (
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
