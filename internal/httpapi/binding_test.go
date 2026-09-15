package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUnbindingTheLastAdministratorsGroupIsRefusedAndChangesNothing drives the
// guard through the route.
//
// It had never executed. `stillAdministrable` sat at 0.0% of its statements,
// and what stood behind it was a delete, a count and a compensating re-insert
// — so a re-insert that failed left the binding gone and nobody able to
// administer, a state whose only route back is editing the database by hand.
//
// Group-bound, because that is the mode the question matters in: with roles
// assigned directly the administrators are people, and a mapping nobody is
// using should still be tidyable.
func TestUnbindingTheLastAdministratorsGroupIsRefusedAndChangesNothing(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		if err := r.rights.BindAdmin(t.Context(), "leads"); err != nil {
			t.Fatal(err)
		}
		// A provider with a source of groups, or the switch below is refused
		// by the guard beside this one and this would prove nothing.
		handler := withProvider(t, r, true)
		ask := func(method, path, body string) *httptest.ResponseRecorder {
			t.Helper()
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			if body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set(testHeader, "admin")
			fromOurOwnPage(req)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec
		}

		if got := ask(http.MethodPut, "/v1/roles/mode",
			`{"mode":"group-bound"}`); got.Code != http.StatusOK {
			t.Fatalf("switching to group-bound answered %d: %s", got.Code, got.Body.String())
		}

		got := ask(http.MethodDelete, "/v1/roles/bindings?group=leads&role=admin", "")
		if got.Code != http.StatusConflict {
			t.Fatalf("unbinding the last administrators' group answered %d, want 409: %s",
				got.Code, got.Body.String())
		}

		// And the binding is still there. The status alone passed while the
		// re-insert put back a row with a fresh timestamp, and would pass
		// again if the delete committed and the refusal came afterwards.
		var listed struct {
			Items []struct {
				Group string `json:"group"`
				Role  string `json:"role"`
			} `json:"items"`
		}
		read(t, r, "admin", "/v1/roles/bindings", &listed)
		found := false
		for _, row := range listed.Items {
			if row.Group == "leads" && row.Role == "admin" {
				found = true
			}
		}
		if !found {
			t.Errorf("a refused unbind took the binding away anyway: %+v", listed.Items)
		}
	})
}
