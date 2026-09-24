// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package outward

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnOpenClientRefusesWhatAnAdministratorExcluded(t *testing.T) {
	// A publisher's description chooses the host. What keeps an internal
	// service on a public name or address out is the excluded list alone.
	excluded, err := ParseExcluded("corp.example.com,203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	client := Open(time.Second, excluded)
	for _, url := range []string{
		"https://corp.example.com/csaf/",
		"https://mirror.corp.example.com/csaf/",
		"https://203.0.113.5/csaf/",
	} {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		// The reason matters: without the check these go on to fail at DNS or
		// at the dial, which would pass while the rule does nothing.
		_, err = client.Transport.RoundTrip(req)
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "an administrator excluded it") {
			t.Errorf("%s: %v, want a refusal naming the exclusion", url, err)
		}
	}
}

func TestAnOpenClientRefusesAnAddressInsideThisNetwork(t *testing.T) {
	// A test server is on loopback, which is refused whatever the list says.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()

	_, err := Open(time.Second, Excluded{}).Get(server.URL)
	if err == nil {
		t.Fatal("an open client reached a server inside this network")
	}
	if !strings.Contains(err.Error(), "not reached inside this network") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestAnOpenClientIsHTTPSOnlyAndFollowsNoRedirect(t *testing.T) {
	client := Open(time.Second, Excluded{})
	req, err := http.NewRequest(http.MethodGet, "http://downloads.example.test/csaf/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Transport.RoundTrip(req); err == nil ||
		!strings.Contains(err.Error(), "reached over https") {
		t.Errorf("plain http: %v, want a refusal naming the scheme", err)
	}
	moved, err := http.NewRequest(http.MethodGet, "https://elsewhere.example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(moved, nil); !errors.Is(err, ErrRefused) {
		t.Errorf("a redirect was followed: %v", err)
	}
}
