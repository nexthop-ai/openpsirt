// Package outward is the one HTTP client this process reaches the internet
// with.
//
// Every fetch out of here goes somewhere named in configuration or in a
// document somebody else published, which is to say from outside, so all of it
// is pinned to the hosts it was told about, refuses redirects, refuses to
// connect inside this network, and is bounded in time.
//
// One package, because a control remembered at each call site is missed at the
// next: a bare client with a timeout and nothing else, or the library's
// default, which has no timeout and follows ten redirects. The call that falls
// back is as likely to be the token exchange, the one carrying a client
// secret, as any other.
package outward

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// Timeout bounds a call out.
//
// The interactive case sets it: somebody is watching a blank page while a
// sign-in runs, and a provider that has stopped answering should fail it
// rather than hold a request open until something further up gives up.
const Timeout = 10 * time.Second

// Guarded returns an HTTP client that will only talk to the hosts named, will
// not follow a redirect, and will not connect to an address inside this
// network.
//
// All three matter because the addresses this client fetches come from
// configuration and from a provider's own discovery document, which is to say
// from outside. An unrestricted client pointed at a discovery document is a
// request forgery primitive: it would fetch whatever the document names, from
// inside the network, with whatever the network trusts this process to reach .
//
// Refusing redirects rather than following them to a checked host is
// deliberate. A redirect is the provider telling us to fetch somewhere else,
// and "somewhere else" is exactly what is being guarded against — a provider
// that genuinely moved its endpoints should be reconfigured, which is visible,
// rather than followed, which is not.
func Guarded(hosts ...string) *http.Client {
	allowed := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		allowed[strings.ToLower(host)] = true
	}

	// Control rather than a wrapped DialContext. DialContext is handed the
	// *unresolved* host and port from the URL, so a check there sees a name
	// and never an address. Control runs once per address the name resolved
	// to, after resolution and before the connection is made, which is both
	// where the address actually exists and the only place a check cannot be
	// slipped past by a name that resolves differently the second time it is
	// asked.
	dialer := &net.Dialer{
		Timeout: Timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			return Reachable(address)
		},
	}
	return &http.Client{
		Timeout: Timeout,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("refused a redirect to %s: a provider's endpoints are configured, not followed", req.URL.Host)
		},
		Transport: &guard{
			allowed: allowed,
			inner:   &http.Transport{DialContext: dialer.DialContext},
		},
	}
}

// guard refuses a request to anywhere but the hosts a provider was configured
// with.
//
// Checked at the round trip rather than only at the dial, because the dial
// sees an address and this sees a name: a request for an unexpected host that
// happens to resolve to a permitted address would pass the first check and
// fail this one.
type guard struct {
	allowed map[string]bool
	inner   http.RoundTripper
}

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("refused a request to %s: a provider is reached over https", req.URL)
	}
	if !g.allowed[strings.ToLower(req.URL.Hostname())] {
		return nil, fmt.Errorf("refused a request to %s: not a configured provider host", req.URL.Hostname())
	}
	return g.inner.RoundTrip(req)
}

// Reachable refuses an address inside this network.
//
// A provider lives on the internet. An address that resolves to somewhere
// private is either a mistake in configuration or a name somebody arranged to
// point inward, and neither is something to connect to and hand a request.
func Reachable(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Reached only from the dialer's control step, which runs on a
		// resolved address. Anything that is not one here is unexpected
		// rather than a name still awaiting resolution.
		return fmt.Errorf("refused a connection to %q: not an address", host)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		sharedAddressSpace(ip) {
		return fmt.Errorf("refused a connection to %s: a provider is not reached inside this network", ip)
	}
	return nil
}

// sharedAddressSpace covers the ranges the standard library does not treat as
// private but which are not the public internet either: the carrier-grade
// translation block, and the block meaning "this network".
func sharedAddressSpace(ip net.IP) bool {
	for _, block := range []string{"100.64.0.0/10", "0.0.0.0/8"} {
		_, network, err := net.ParseCIDR(block)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
