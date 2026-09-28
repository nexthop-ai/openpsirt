// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// refusedWith pins the status a refusal answers with.
//
// A bound such as `got.Code < 400` also holds for a 404 from a renamed route, a
// 422 for an unrelated body rule, a 403 that says a hidden product exists, and
// the 500 chi's recovery middleware makes of a panic. An exact status is the
// only assertion none of those satisfy.
func refusedWith(t *testing.T, got *httptest.ResponseRecorder, want int) {
	t.Helper()
	if got.Code != want {
		t.Fatalf("got %d %s, want %d %s: %s", got.Code, http.StatusText(got.Code),
			want, http.StatusText(want), got.Body.String())
	}
}
