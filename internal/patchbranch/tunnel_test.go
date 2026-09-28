// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/outward"
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
	door, err := openGuard(host, outward.Excluded{})
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

// The address a name resolved to is checked against the administrator's
// excluded networks at the moment of connecting.
//
// The tunnel is asked for by a name no exclusion mentions, which resolves to
// a listener in a network an exclusion does name, so only the connect-time
// check stands between the tunnel and the listener. Verified by deleting the
// dialer's Control in guard.tunnel: the tunnel opens with 200.
func TestTheGuardRefusesAnAddressInAnExcludedNetworkWhateverNameReachedIt(t *testing.T) {
	listening := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer listening.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(listening.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	excluded, err := outward.ParseExcluded("127.0.0.0/8, ::1")
	if err != nil {
		t.Fatal(err)
	}
	door, err := openGuard("localhost", excluded)
	if err != nil {
		t.Fatal(err)
	}
	defer door.close()
	if excluded.Host("localhost") {
		t.Fatal("the name itself was excluded, so this tests nothing about the address")
	}
	// The port is relaxed to the listener's; the address check stays as
	// openGuard made it.
	door.port = port

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(door.address(), "http://"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	target := net.JoinHostPort("localhost", port)
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusOK {
		t.Fatal("the guard opened a tunnel to an address in an excluded network")
	}
	reason, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(reason), "an administrator excluded it") {
		t.Errorf("the tunnel was refused for another reason: %d %s", response.StatusCode, reason)
	}
}
