// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestATunnelTheGuardOpensCarriesTLSEndToEnd(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "from the repository")
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(target.Host)
	if err != nil {
		t.Fatal(err)
	}
	// The server is on this machine, which the guard refuses; the test
	// relaxes that and the port, and nothing else.
	door, err := openGuard(host, Excluded{})
	if err != nil {
		t.Fatal(err)
	}
	defer door.close()
	door.port = port
	door.reachable = func(string) error { return nil }

	proxy, err := url.Parse(door.address())
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxy)
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "from the repository" {
		t.Errorf("the tunnel carried %q", body)
	}
}

func TestTheGuardRefusesAnAddressInAnExcludedNetworkWhateverNameReachedIt(t *testing.T) {
	excluded, err := ParseExcluded("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	// A public name the administrator never mentioned, resolving into a
	// network they did. The name passes; the address it resolved to does not.
	door, err := openGuard("git.example.org", excluded)
	if err != nil {
		t.Fatal(err)
	}
	defer door.close()
	if excluded.Host("git.example.org") {
		t.Fatal("the name itself was excluded, so this tests nothing about the address")
	}
	if err := door.reachable("203.0.113.9:443"); err == nil {
		t.Error("the guard would connect to an address in an excluded network")
	}
	if err := door.reachable("198.51.100.9:443"); err != nil {
		t.Errorf("the guard refused an address outside every excluded network: %v", err)
	}
}
