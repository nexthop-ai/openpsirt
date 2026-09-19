package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// meantToBeSent reports whether a state-changing request was made by one of
// our own pages rather than by somebody else's.
//
// Two mechanisms, because the two ways a browser can arrive here need
// different ones.
//
// A session of ours carries a value that our pages read and echo. A page from
// another origin cannot read it, so echoing it correctly is proof.
//
// The trusted-header path has no session to hold such a value: the proxy
// authenticates from its own cookie, which the browser attaches without
// anybody asking. That is exactly the property forgery exploits, so the guard
// is needed there too — and what is left to check is where the request came
// from. A browser sets Origin on every state-changing request and will not let
// a page lie about it, so a request that names another origin, or names none
// at all, is not one of ours.
func meantToBeSent(r *http.Request, session *access.Session, base string) bool {
	if session == nil || !changesSomething(r.Method) {
		return true
	}

	// The request's origin is checked for every browser arrival,
	// including one carrying a session. It costs nothing and it holds when the
	// echoed value has leaked.
	if !sameOrigin(r, base) {
		return false
	}
	if access.FromBrowserWithoutSession(session) {
		return true
	}
	return session.MatchesCSRF(r.Header.Get(access.CSRFHeader))
}

// sameOrigin reports whether a request came from where this deployment is
// served.
//
// Compared against the configured address where there is one. Without it the
// request's own Host is used, which is sound for exactly this purpose: a
// hostile page cannot make a browser send some other site's Host, and the
// Origin it sends is the page's own rather than one it chose.
func sameOrigin(r *http.Request, base string) bool {
	stated := r.Header.Get("Origin")
	if stated == "" {
		// Older browsers, and a few request shapes, send Referer instead.
		// Its origin is the part that matters.
		if referrer := r.Header.Get("Referer"); referrer != "" {
			if parsed, err := url.Parse(referrer); err == nil && parsed.Host != "" {
				stated = parsed.Scheme + "://" + parsed.Host
			}
		}
	}
	if stated == "" {
		// Neither header. A browser sends one of them on a state-changing
		// request, so this is something else — and refusing is the safe
		// reading, since anything that is not a browser can present a
		// credential that carries no forgery risk instead.
		return false
	}

	for _, ours := range origins(r, base) {
		if strings.EqualFold(stated, ours) {
			return true
		}
	}
	return false
}

// origins is where this deployment answers, as a browser would name it.
//
// A configured address that yields no host matches nothing, rather than
// falling through to the request's own. Falling through turns the check into
// an echo of the Host header the request supplied — the guard runs, passes and
// guards nothing, while the operator believes they have pinned the origin.
// `config.Load` refuses such a value at startup, so reaching here with one
// means it arrived another way; answering nothing is the safe half of
// that, and it is a refusal a person meets immediately rather than a hole
// nobody meets at all.
func origins(r *http.Request, base string) []string {
	if base != "" {
		parsed, err := url.Parse(strings.TrimSuffix(base, "/"))
		if err != nil || parsed.Host == "" {
			return nil
		}
		return []string{parsed.Scheme + "://" + parsed.Host}
	}
	if r.Host == "" {
		return nil
	}
	// Both schemes, because what reaches this process says nothing about what
	// the browser used to reach whatever is in front of it.
	return []string{"https://" + r.Host, "http://" + r.Host}
}
