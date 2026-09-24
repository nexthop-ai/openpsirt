// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
)

func TestAnExcludedNameCoversTheHostsUnderItAndNoOthers(t *testing.T) {
	excluded, err := outward.ParseExcluded(" corp.example.com , .lab.example.org,10.20.0.0/16, 192.0.2.7 ")
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"corp.example.com":     true,
		"git.corp.example.com": true,
		"GIT.CORP.EXAMPLE.COM": true,
		"lab.example.org":      true,
		"a.b.lab.example.org":  true,
		"evilcorp.example.com": false,
		"example.com":          false,
		"github.com":           false,
		"10.20.3.4":            true,
		"10.21.3.4":            false,
		"192.0.2.7":            true,
		"192.0.2.8":            false,
	} {
		if got := excluded.Host(host); got != want {
			t.Errorf("%s excluded = %v, want %v", host, got, want)
		}
	}
}

func TestAnAddressAnExcludedNetworkHoldsIsRefusedWhateverNameReachedIt(t *testing.T) {
	excluded, err := outward.ParseExcluded("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := excluded.Reachable("203.0.113.9:443"); err == nil {
		t.Error("an address in an excluded network was reachable")
	}
	if err := excluded.Reachable("198.51.100.9:443"); err != nil {
		t.Errorf("an address outside every excluded network was refused: %v", err)
	}
	// This network is refused with nothing configured at all.
	for _, address := range []string{"127.0.0.1:443", "10.0.0.1:443", "192.168.1.1:443", "169.254.169.254:443", "[::1]:443"} {
		if err := (outward.Excluded{}).Reachable(address); err == nil {
			t.Errorf("%s was reachable with nothing excluded", address)
		}
	}
}

func TestAnExclusionThatIsNeitherANameNorANetworkIsRefused(t *testing.T) {
	for _, bad := range []string{"10.0.0.0/33", "host name", "https://corp.example.com", "corp.example.com:443"} {
		if _, err := outward.ParseExcluded(bad); err == nil {
			t.Errorf("%q was accepted as an exclusion", bad)
		}
	}
}

// tunnel asks the guard for a tunnel and answers the status it gave, and the
// reason where it gave one.
func tunnel(t *testing.T, proxy, method, target string) (int, string) {
	t.Helper()
	address, err := url.Parse(proxy)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", address.Host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, target, target); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusOK {
		return response.StatusCode, ""
	}
	reason, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(reason)
}

func TestTheGuardOpensNoTunnelGitWasNotSentThrough(t *testing.T) {
	excluded, err := outward.ParseExcluded("corp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Each refused before anything is dialed, or at the dial by the address
	// check, so each names the rule that stopped it. A case refused for some
	// other reason — a name that does not resolve — would pass with the rule
	// it is about removed.
	for _, each := range []struct {
		why, host, method, target, says string
	}{
		{"a plain request rather than a tunnel", "github.com", http.MethodGet, "github.com:443", "not for a tunnel"},
		{"a port other than https", "github.com", http.MethodConnect, "github.com:22", "https port"},
		{"a host other than the repository's", "github.com", http.MethodConnect, "example.org:443", "this fetch is from"},
		{"a host an administrator excluded", "git.corp.example.com", http.MethodConnect, "git.corp.example.com:443", "excluded"},
		{"a name that resolves inside this network", "localhost", http.MethodConnect, "localhost:443", "inside this network"},
		{"an address inside this network", "127.0.0.1", http.MethodConnect, "127.0.0.1:443", "inside this network"},
	} {
		proxy, stop, err := patchbranch.OpenGuard(each.host, excluded)
		if err != nil {
			t.Fatal(err)
		}
		status, reason := tunnel(t, proxy, each.method, each.target)
		stop()
		if status == http.StatusOK {
			t.Errorf("%s: the guard opened a tunnel", each.why)
		} else if !strings.Contains(reason, each.says) {
			t.Errorf("%s: refused for another reason: %s", each.why, reason)
		}
	}
}

func TestGitIsToldToReachOutThroughTheGuardAndNothingElse(t *testing.T) {
	// A repository on a host that resolves inside this network. The fetch
	// fails at the guard, and what it reports is the guard's reason rather
	// than git's account of a proxy that said no.
	excluded := outward.Excluded{}
	pass := patchbranch.NewRemotePass(t.TempDir(), excluded)
	err := pass.Fetch(t.Context(), "https://localhost/example/project.git")
	if err == nil {
		t.Fatal("a repository inside this network was fetched")
	}
	if !strings.Contains(err.Error(), "inside this network") {
		t.Errorf("the refusal did not say why: %v", err)
	}
}
