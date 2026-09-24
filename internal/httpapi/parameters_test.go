// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestAQueryParameterNoOperationTakesIsRefusedByName pins both halves: a
// parameter the operation declares is answered, and one it does not is
// refused naming it rather than ignored. Ignored, a mistyped filter returns
// the unfiltered list, which reads as a correct answer.
func TestAQueryParameterNoOperationTakesIsRefusedByName(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		if got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings?stream=master", ""); got.Code != http.StatusOK {
			t.Fatalf("a declared parameter answered %d: %s", got.Code, got.Body.String())
		}

		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings?stream=master&stat=open", "")
		if got.Code != http.StatusBadRequest {
			t.Fatalf("an undeclared parameter answered %d, want 400: %s",
				got.Code, got.Body.String())
		}
		if !strings.Contains(got.Body.String(), "stat") {
			t.Errorf("the refusal does not name the parameter: %s", got.Body.String())
		}

		// A caller who may not reach the operation is refused as that first,
		// so the refusal says nothing about what the operation takes.
		if got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/settings?stat=open", ""); got.Code != http.StatusForbidden {
			t.Errorf("an operation the caller may not reach answered %d, want 403", got.Code)
		}
	})
}
