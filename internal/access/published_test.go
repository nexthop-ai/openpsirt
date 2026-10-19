// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Anybody at all reads disclosed work in the products that publish and
// nothing else: not undisclosed work there, not a product that does not
// publish, and no role, case, team or hold over the deployment anywhere.
func TestAnybodyReadsOnlyDisclosedWorkWhereItIsPublished(t *testing.T) {
	const published, other = 7, 8
	anybody := access.Published([]int64{published})
	if !anybody.Reads(access.Public, published) {
		t.Error("anybody does not read disclosed work in a product that publishes")
	}
	for _, refused := range []struct {
		what    string
		answers bool
	}{
		{"undisclosed work where it is published", anybody.Reads(access.Private, published)},
		{"disclosed work in a product that does not publish", anybody.Reads(access.Public, other)},
		{"that a product that does not publish exists", anybody.Sees(other)},
		{"a role", anybody.Holds(access.PublicRead, published)},
		{"triage", anybody.Triages(access.Public, published)},
		{"a role anywhere", anybody.HoldsAnywhere(access.Roles()...)},
		{"the deployment's own records", anybody.ReadsTheDeployment()},
		{"a case", anybody.OnCase(published, 1)},
		{"everything", anybody.Unnarrowed()},
	} {
		if refused.answers {
			t.Errorf("anybody holds %s", refused.what)
		}
	}
	if err := anybody.Administering("anything"); err == nil {
		t.Error("anybody administers")
	}
	if products, all := anybody.Products(); all || !slices.Equal(products, []int64{published}) {
		t.Errorf("anybody reads products %v (all %v), want the one that publishes", products, all)
	}
	if mine := anybody.Mine(); len(mine) != 0 {
		t.Errorf("anybody holds work as %v", mine)
	}
	if nobody := access.Published(nil); nobody.Reads(access.Public, published) {
		t.Error("anybody reads a product where nothing publishes")
	}
}

// The client a request is counted against is the connection, unless the
// connection is a trusted proxy: then it is the first address from the right
// of what the proxies forwarded that is not itself a trusted proxy. What a
// client wrote to the left of that, and anything an untrusted connection
// sends, is never read.
func TestTheClientIsTheRightmostAddressNoTrustedProxyHolds(t *testing.T) {
	_, proxies, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	trust := access.Trust{From: []net.IPNet{*proxies}}
	for _, tc := range []struct {
		what, remote string
		forwarded    []string
		want         string
	}{
		{"a connection with nothing forwarded", "198.51.100.7:4000", nil, "198.51.100.7"},
		{"an untrusted connection forging a header", "198.51.100.7:4000", []string{"203.0.113.1"}, "198.51.100.7"},
		{"a trusted proxy forwarding a client", "10.0.0.5:4000", []string{"203.0.113.1"}, "203.0.113.1"},
		{"a client forging the left of what the proxy forwards", "10.0.0.5:4000",
			[]string{"192.0.2.66, 203.0.113.1"}, "203.0.113.1"},
		{"two trusted proxies in a row", "10.0.0.5:4000", []string{"203.0.113.1, 10.1.1.1"}, "203.0.113.1"},
		{"the hops in two headers", "10.0.0.5:4000", []string{"192.0.2.66", "203.0.113.1"}, "203.0.113.1"},
		{"a hop that is not an address", "10.0.0.5:4000", []string{"203.0.113.1, unknown"}, "10.0.0.5"},
		{"a hop carrying its port", "10.0.0.5:4000", []string{"203.0.113.1:51234"}, "203.0.113.1"},
		{"an IPv6 hop carrying its port", "10.0.0.5:4000", []string{"[2001:db8::7]:51234"}, "2001:db8::7"},
		{"a trusted proxy forwarding nothing", "10.0.0.5:4000", nil, "10.0.0.5"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = tc.remote
		for _, line := range tc.forwarded {
			req.Header.Add("X-Forwarded-For", line)
		}
		if got := trust.Client(req); got != tc.want {
			t.Errorf("%s: counted as %s, want %s", tc.what, got, tc.want)
		}
	}
}
