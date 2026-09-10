package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTheRefusalEverybodyMeetsFirstHasTheDocumentedShape(t *testing.T) {
	// Every request arriving without a credential gets this one, which makes
	// it the most-answered refusal in the API and the first thing a client
	// written against the error model meets. It was a string literal beside
	// the model rather than the model, so it carried neither the schema link
	// nor the fields every other refusal has.
	twoReach(t, func(t *testing.T, r *reach) {
		request := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		got := httptest.NewRecorder()
		r.handler.ServeHTTP(got, request)
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
		read(t, r, "triager", "/v1/products", &named)
		bad := asPerson(t, r, "triager", http.MethodGet, "/v1/products/nosuch/streams", "")
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

func TestASignInThatWillNotCompleteRefusesInTheSameShape(t *testing.T) {
	// The sign-in callbacks are ordinary handlers rather than operations,
	// because a redirect arriving from a provider is not an API call — and
	// they answered `text/plain` while everything else answered
	// `application/problem+json`. A client that parses one shape and gets the
	// other reads a refusal as a transport fault, and the shape of a refusal
	// is part of the answer.
	eachSignIn(t, func(t *testing.T, r *signInReach) {
		// A callback with nothing pending, which is the refusal every
		// one of the reasons collapses into: a provider that failed, a
		// state that did not match, somebody unknown, and somebody
		// known and granted nothing all answer alike.
		got := callback(t, r, "whatever", "code", false)
		if got.Code != http.StatusUnauthorized {
			t.Fatalf("a callback with nothing pending answered %d: %s",
				got.Code, got.Body.String())
		}
		if kind := got.Header().Get("Content-Type"); kind != "application/problem+json" {
			t.Errorf("a refused sign-in came back as %q, not the shape every other "+
				"refusal takes: %s", kind, got.Body.String())
		}
		var refused map[string]any
		if err := json.Unmarshal(got.Body.Bytes(), &refused); err != nil {
			t.Fatalf("a refused sign-in is not readable as JSON: %v (%s)",
				err, got.Body.String())
		}
		for _, field := range []string{"title", "status", "detail"} {
			if _, held := refused[field]; !held {
				t.Errorf("the refusal is missing %q: %s", field, got.Body.String())
			}
		}
	})
}
