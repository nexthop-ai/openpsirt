package httpapi_test

import (
	"net/http"
	"testing"
)

func TestAPlanIsWrittenAsASetAndReadBackAsWhatTheScansSay(t *testing.T) {
	// The route mirrors assignment: the path says which finding is being
	// looked at, and what is planned belongs to the work it is part of.
	//
	// Nothing here is declared done. A build is clear when it stops
	// holding the issue, and a build nobody chose reads as undecided
	// rather than as outstanding work.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/fix-targets"

		var plan struct {
			Items []struct {
				Stream     string `json:"stream"`
				Variant    string `json:"variant"`
				Places     int    `json:"places"`
				State      string `json:"state"`
				DeclaredBy string `json:"declared_by"`
			} `json:"items"`
			Declared int  `json:"declared"`
			Clear    int  `json:"clear"`
			Missed   int  `json:"missed"`
			Resolved bool `json:"resolved"`
		}

		read(t, r, "triager", at, &plan)
		if len(plan.Items) != 1 || plan.Items[0].State != "undecided" {
			t.Fatalf("before anybody plans anything the build reads as %+v", plan.Items)
		}
		if plan.Declared != 0 || plan.Resolved {
			t.Errorf("nothing is planned and the answer says declared=%d resolved=%v",
				plan.Declared, plan.Resolved)
		}

		// Reading is reading; saying what will be fixed is triage work.
		if got := asPerson(t, r, "reader", http.MethodPut, at,
			`{"builds":[{"stream":"master","variant":"broadcom"}]}`); got.Code < 400 {
			t.Errorf("somebody who may only read set the plan: %d", got.Code)
		}

		got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"builds":[{"stream":"master","variant":"broadcom"}]}`)
		if got.Code != http.StatusOK {
			t.Fatalf("setting the plan answered %d: %s", got.Code, got.Body.String())
		}

		read(t, r, "triager", at, &plan)
		if len(plan.Items) != 1 || plan.Items[0].State != "fixing" {
			t.Fatalf("after planning it, the build reads as %+v", plan.Items)
		}
		if plan.Items[0].DeclaredBy == "" {
			t.Error("the plan does not say who made it")
		}
		if plan.Declared != 1 || plan.Clear != 0 || plan.Resolved {
			t.Errorf("one build planned and nothing shipped reads as declared=%d clear=%d resolved=%v",
				plan.Declared, plan.Clear, plan.Resolved)
		}

		// An empty set withdraws it, which is the same operation rather than a
		// second path that drifts.
		if got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"builds":[]}`); got.Code != http.StatusOK {
			t.Fatalf("withdrawing the plan answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "triager", at, &plan)
		if plan.Declared != 0 || plan.Items[0].State != "undecided" {
			t.Errorf("after withdrawing, the build reads as %+v (declared %d)",
				plan.Items, plan.Declared)
		}
	})
}

func TestAPlanNamesAReleaseAndNeverAProduct(t *testing.T) {
	// The body names a release and a variant, never a product, so reaching
	// into another product's builds is not something a request can express
	// — what is resolved is a release *of the product in the path*. A name
	// this product does not have is refused as though it were not there,
	// the same answer a release nobody ever declared gets, so guessing
	// teaches nothing . The store refuses a build of another product too,
	// for the callers that name one by identifier.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/fix-targets"

		got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"builds":[{"stream":"master","variant":"mellanox"}]}`)
		if got.Code < 400 {
			t.Errorf("a build of another product was accepted into the plan: %d %s",
				got.Code, got.Body.String())
		}
	})
}
