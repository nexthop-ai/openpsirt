// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestTheRefusalEverybodyMeetsFirstHasTheDocumentedShape(t *testing.T) {
	// Every request arriving without a credential gets this one, which makes
	// it the most-answered refusal in the API and the first thing a client
	// written against the error model meets. It was a string literal beside
	// the model rather than the model, so it carried neither the schema link
	// nor the fields every other refusal has.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		request := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		got := httptest.NewRecorder()
		r.Handler.ServeHTTP(got, request)
		if got.Code != http.StatusUnauthorized {
			t.Fatalf("a request with no credential answered %d", got.Code)
		}
		if kind := got.Header().Get("Content-Type"); kind != "application/problem+json" {
			t.Errorf("the refusal came back as %q", kind)
		}
		var refused map[string]any
		if err := json.Unmarshal(got.Body.Bytes(), &refused); err != nil {
			t.Fatalf("the refusal is not readable as JSON: %v (%s)", err, got.Body.String())
		}
		// The same fields a refusal from any operation carries.
		var named map[string]any
		httpapitest.Read(t, r, "triager", "/v1/products", &named)
		bad := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/products/nosuch/branches-and-tags", "")
		var other map[string]any
		if err := json.Unmarshal(bad.Body.Bytes(), &other); err != nil {
			t.Fatal(err)
		}
		for field := range other {
			// `detail` and `errors` differ per refusal by design. `$schema` is
			// added by the API's own response transformer, and this refusal is
			// written before the request reaches it — the credential is
			// resolved in front of the router, because an unrecognized one
			// must not reach an operation at all. That is the one field this
			// answer cannot carry, and it is named here rather than left to
			// look like an oversight.
			if field == "detail" || field == "errors" || field == "$schema" {
				continue
			}
			if _, held := refused[field]; !held {
				t.Errorf("the refusal is missing %q, which every other refusal carries: %s",
					field, got.Body.String())
			}
		}
	})
}
