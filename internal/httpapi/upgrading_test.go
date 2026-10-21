// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The answer while the schema is applied is a page a browser opens like any
// other, so it carries the headers every response from the router carries.
func TestTheUpgradingAnswerCarriesTheBrowserHeaders(t *testing.T) {
	h := Upgrading()
	for _, path := range []string{"/healthz", "/readyz", "/v1/version", "/"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept", "text/html")
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("GET %s: X-Content-Type-Options = %q", path, got)
		}
		if policy := rec.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "script-src 'self'") {
			t.Errorf("GET %s: the policy is %q", path, policy)
		}
	}
}
