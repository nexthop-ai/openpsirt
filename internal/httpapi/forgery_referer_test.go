// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A request carrying no Origin is judged by the origin of its Referer, which
// some browsers and request shapes send instead. The origin is the scheme and
// the host, compared whole: a host that merely begins with ours, a Referer
// that names no host, and an opaque Origin are all somewhere else.
//
// Verified by deleting the Referer arm of sameOrigin: the request from our own
// page is then refused for naming no origin.
func TestARefererStandsInForAMissingOrigin(t *testing.T) {
	const base = "https://psirt.example.com"
	for _, c := range []struct {
		what    string
		origin  string
		referer string
		want    bool
	}{
		{"our own page", "", "https://psirt.example.com/findings?page=2", true},
		{"our own page, spelled with capitals", "", "https://PSIRT.example.com/x", true},
		{"a host that begins with ours", "", "https://psirt.example.com.attacker.example/", false},
		{"another scheme", "", "http://psirt.example.com/x", false},
		{"a Referer that names no host", "", "/findings", false},
		{"a Referer that does not parse", "", "https://psirt.example.com/%zz", false},
		{"neither header", "", "", false},
		{"an opaque Origin", "null", "https://psirt.example.com/x", false},
		{"an Origin beside a Referer that disagrees", "https://attacker.example",
			"https://psirt.example.com/x", false},
	} {
		asked := httptest.NewRequest(http.MethodPost, "/v1/products", nil)
		asked.Host = "psirt.example.com"
		if c.origin != "" {
			asked.Header.Set("Origin", c.origin)
		}
		if c.referer != "" {
			asked.Header.Set("Referer", c.referer)
		}
		if got := sameOrigin(asked, base); got != c.want {
			t.Errorf("%s: answered %v, want %v", c.what, got, c.want)
		}
	}
}
