// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package outward is the one HTTP client this process reaches the internet
// with.
//
// Every fetch through here goes somewhere named in configuration or in a
// document somebody else published, which is to say from outside, so all of it
// refuses redirects, refuses to connect inside this network, and is bounded in
// time (REQ-69). A client whose hosts are known in advance is pinned to them;
// the open client, for hosts a document chooses, also refuses anywhere an
// administrator excluded. Webhooks, mail and the object store do not reach out
// through here, and each governs its own address.
//
// One package, because a control remembered at each call site is missed at the
// next: a bare client with a timeout and nothing else, or the library's
// default, which has no timeout and follows ten redirects. The call that falls
// back is as likely to be the token exchange, the one carrying a client
// secret, as any other.
package outward

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	return GuardedWithin(Timeout, hosts...)
}

// GuardedWithin is Guarded with a budget of its own.
//
// Timeout is sized for somebody watching a blank page while a sign-in runs, and
// it bounds the whole call rather than the wait for a first byte. A caller
// fetching a document whose bound is measured in hundreds of megabytes needs a
// budget in proportion: at the interactive one, a document too large to arrive
// in ten seconds cannot be fetched at all, however many times it is tried.
//
// Everything else is Guarded's: the host allowlist, the refusal to follow a
// redirect, and the refusal to connect inside this network. The dialer keeps
// the interactive budget whatever the whole call is given, because how long a
// connection takes to establish does not scale with what is being fetched.
func GuardedWithin(within time.Duration, hosts ...string) *http.Client {
	allowed := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		allowed[strings.ToLower(host)] = true
	}
	return client(within, Reachable, func(to *url.URL) error {
		host := to.Hostname()
		if !allowed[strings.ToLower(host)] {
			return fmt.Errorf("%w a request to %s: not a configured provider host", ErrRefused, host)
		}
		return nil
	})
}

// Open returns an HTTP client for addresses a publisher's own document names,
// which may be on any host outside this network and outside what an
// administrator excluded.
//
// The same refusals as Guarded apart from the allowlist: https only, no
// redirect followed, and no connection to an address inside this network or
// in an excluded one — checked on the address a name resolved to, at the
// moment of connecting. Before anything is resolved, a request is refused
// that names a host excluded by name, a host that is not a plain name or
// address, a port other than the https one, or a user.
//
// A plain name is checked because the transport maps a name written in other
// scripts to the one it resolves: a fullwidth letter in a host passes a
// comparison against the excluded names and then dials the host they name.
// The port is checked because the addresses come from a publisher's document,
// and one naming every port on a host would make the fetcher a port scanner
// whose findings come back in the supplier's error.
func Open(within time.Duration, excluded Excluded) *http.Client {
	return open(within, excluded, "443")
}

// open is Open with the one port it reaches named, so a test can point it at
// a server on a port of its own.
func open(within time.Duration, excluded Excluded, port string) *http.Client {
	return client(within, excluded.Reachable, func(to *url.URL) error {
		host := strings.ToLower(strings.TrimSuffix(to.Hostname(), "."))
		switch {
		case to.User != nil:
			return fmt.Errorf("%w a request to %s: an address carries no user", ErrRefused, host)
		case to.Port() != "" && to.Port() != port:
			return fmt.Errorf("%w a request to %s on port %s: only the https port is reached",
				ErrRefused, host, to.Port())
		case net.ParseIP(host) == nil && !HostName(host):
			return fmt.Errorf("%w a request to %q: not a host name", ErrRefused, to.Hostname())
		case excluded.Host(host):
			return fmt.Errorf("%w a request to %s: an administrator excluded it", ErrRefused, host)
		}
		return nil
	})
}

// client is the one shape every outbound client here takes: an address check
// at the dial, a host check at the round trip, redirects refused, and a budget
// for the whole call.
func client(within time.Duration, reachable func(string) error,
	permits func(to *url.URL) error) *http.Client {

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
			return reachable(address)
		},
	}
	return &http.Client{
		Timeout: within,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("%w a redirect to %s: a provider's endpoints are configured, not followed",
				ErrRefused, req.URL.Host)
		},
		Transport: &guard{
			permits: permits,
			inner:   &http.Transport{DialContext: dialer.DialContext},
		},
	}
}

// ErrRefused says the guarded client turned a request away itself: a redirect,
// a scheme other than https, a host nobody configured, or a host an
// administrator excluded. Nothing was asked of
// the address, so a caller can tell this from a provider that did not answer.
var ErrRefused = errors.New("refused")

// guard refuses a request to a host the client does not permit.
//
// Checked at the round trip rather than only at the dial, because the dial
// sees an address and this sees a name: a request for an unexpected host that
// happens to resolve to a permitted address would pass the first check and
// fail this one.
type guard struct {
	permits func(to *url.URL) error
	inner   http.RoundTripper
}

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("%w a request to %s: a provider is reached over https", ErrRefused, req.URL)
	}
	if err := g.permits(req.URL); err != nil {
		return nil, err
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
// translation block, the block meaning "this network", and the two prefixes a
// NAT64 gateway translates into IPv4 — on a network with DNS64, a name
// answering 64:ff9b::a00:5 reaches 10.0.0.5.
func sharedAddressSpace(ip net.IP) bool {
	for _, block := range []string{"100.64.0.0/10", "0.0.0.0/8", "64:ff9b::/96", "64:ff9b:1::/48"} {
		_, network, err := net.ParseCIDR(block)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
