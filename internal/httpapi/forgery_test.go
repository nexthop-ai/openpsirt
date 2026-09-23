// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The address this deployment answers on, as a browser would name it, and the
// input to the same-origin check on every state-changing browser request.
//
// A configured address that yields no host falls through to origins derived
// from the request's own Host header, so the guard echoes what the request
// said: it still ran, still passed, and guarded nothing, while the operator
// believed the origin was pinned. `psirt.example.com` is the form that
// produces it, and the form the value takes in a DNS record.

func TestAConfiguredAddressThatNamesNoHostMatchesNothing(t *testing.T) {
	asked := httptest.NewRequest(http.MethodPost, "/v1/products", nil)
	asked.Host = "attacker.example"

	for _, c := range []struct {
		what string
		base string
		want []string
	}{
		{
			"an address, which is what pins the origin",
			"https://psirt.example.com", []string{"https://psirt.example.com"},
		},
		{
			"one with a trailing slash",
			"https://psirt.example.com/", []string{"https://psirt.example.com"},
		},
		{
			// Both schemes, because what reaches this process says nothing
			// about what the browser used to reach whatever is in front of it.
			"nothing configured, which is the deployment behind a proxy",
			"", []string{"https://attacker.example", "http://attacker.example"},
		},
		{
			"a bare host, which names no host to url.Parse",
			"psirt.example.com", nil,
		},
		{
			"something that is not an address at all",
			"https://%zz", nil,
		},
	} {
		got := origins(asked, c.base)
		if len(got) != len(c.want) {
			t.Errorf("%s (%q): answered %v, want %v", c.what, c.base, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s (%q): answered %v, want %v", c.what, c.base, got, c.want)
				break
			}
		}
	}
}

func TestAMisconfiguredAddressDoesNotBecomeTheRequestsOwn(t *testing.T) {
	// The whole of the defect in one assertion: with a base configured, the
	// request's Host must never be what the check compares against. It was,
	// and a page on any host could then make a state-changing request that
	// passed.
	asked := httptest.NewRequest(http.MethodPost, "/v1/products", nil)
	asked.Host = "attacker.example"
	asked.Header.Set("Origin", "https://attacker.example")

	if sameOrigin(asked, "psirt.example.com") {
		t.Error("a request from another host matched a deployment address that names no host")
	}
	// And a correctly configured one still refuses it, which is the control
	// working rather than the input being unusable.
	if sameOrigin(asked, "https://psirt.example.com") {
		t.Error("a request from another host matched the configured origin")
	}
	// The other direction: the deployment's own page is not refused.
	ours := httptest.NewRequest(http.MethodPost, "/v1/products", nil)
	ours.Host = "psirt.example.com"
	ours.Header.Set("Origin", "https://psirt.example.com")
	if !sameOrigin(ours, "https://psirt.example.com") {
		t.Error("a request from our own page was refused")
	}
}
