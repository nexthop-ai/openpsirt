package access

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// Trust says how a person's identity may reach us.
//
// A reverse proxy authenticates and passes the username on in a header. That
// lets a deployment run with no provider at all, and supports operators who
// already authenticate at their ingress.
//
// Both guardrails are deliberate acts. Trusting the header unconditionally
// would let anybody able to reach the application directly become anybody at
// all, administrator included — reaching the container bypasses the proxy
// entirely. And it is never a fallback for unconfigured sign-in, because that
// is how it ends up live by accident.
type Trust struct {
	// Header is the name the proxy sets. Empty means header sign-in is off.
	Header string
	// From are the addresses the header is honored from. Header sign-in
	// without one of these is refused rather than trusted.
	From []net.IPNet
	// GroupsHeader is where the proxy reports membership, and
	// GroupsDelimiter what separates the names in it. Neither is
	// standardized, so both are named rather than guessed. Empty means
	// membership is not read from the proxy at all.
	GroupsHeader    string
	GroupsDelimiter string
}

// Enabled reports whether header sign-in is on.
func (t Trust) Enabled() bool { return t.Header != "" && len(t.From) > 0 }

// Configured reports a half-configuration, which is the dangerous state: a
// header named with nothing to trust it from is either a mistake or the first
// half of one.
func (t Trust) Configured() error {
	switch {
	case t.Header == "" && len(t.From) == 0:
		return nil
	case t.Header == "":
		return fmt.Errorf("trusted sources are configured but no header is named, so nothing would be read from them")
	case len(t.From) == 0:
		return fmt.Errorf("a trusted header is named but no source is trusted, and honoring it from anywhere would let anyone reaching this process be anyone")
	}
	// Naming every address reaches the same place as naming none, by the one
	// setting that is supposed to be the guard. Halting on the empty case and
	// accepting this one would be a guard that only catches the honest
	// mistake.
	for _, network := range t.From {
		if ones, _ := network.Mask.Size(); ones == 0 {
			return fmt.Errorf("a trusted header is honored from every address, which is the same as trusting it from anywhere")
		}
	}
	return nil
}

// groupsFrom reads the membership a proxy reported.
//
// Neither header is standardized and neither is the separator, so both are
// configured: oauth2-proxy sends X-Auth-Request-Groups comma-separated,
// Authelia sends Remote-Groups, and others differ again. A header
// nobody named yields nothing, which is the same answer an empty one gives —
// no roles, never unrestricted.
func (t Trust) groupsFrom(req *http.Request) []string {
	if t.GroupsHeader == "" {
		return nil
	}
	separator := t.GroupsDelimiter
	if separator == "" {
		separator = ","
	}
	var names []string
	for _, name := range strings.Split(req.Header.Get(t.GroupsHeader), separator) {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			names = append(names, trimmed)
		}
	}
	return names
}

// trusts reports whether a request came from somewhere the header is honored.
func (t Trust) trusts(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, allowed := range t.From {
		if allowed.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolver turns a request into the subject making it.
type Resolver struct {
	store *Store
	trust Trust
	// logger records a refusal an operator would otherwise have to guess at.
	// What the caller is told never changes.
	logger *slog.Logger
	// mode says where roles come from. It is read per request rather than
	// held, because an administrator can change it without a restart and a
	// held copy would keep deriving roles after they turned it off.
	mode func(context.Context) Mode
	// plainHTTP says this deployment is served without TLS, which is the one
	// case the cookie prefix has to be dropped for — a browser will not set a
	// `__Host-` cookie over plain HTTP, so keeping the prefix there makes
	// every sign-in silently fail.
	plainHTTP bool
}

// NewResolver returns a resolver over a store.
func NewResolver(store *Store, trust Trust) *Resolver {
	return &Resolver{
		store: store, trust: trust, logger: slog.Default(),
		// Direct until told otherwise: the mode in which nothing is derived
		// from what a provider says.
		mode: func(context.Context) Mode { return Direct },
	}
}

// WithMode tells the resolver where roles come from.
func (r *Resolver) WithMode(mode func(context.Context) Mode) *Resolver {
	if mode != nil {
		r.mode = mode
	}
	return r
}

// OverPlainHTTP says this deployment is served without TLS, which changes the
// name the session cookie is read under.
func (r *Resolver) OverPlainHTTP(plain bool) *Resolver {
	r.plainHTTP = plain
	return r
}

// WithLogger sends refusals worth an operator's attention to l.
func (r *Resolver) WithLogger(l *slog.Logger) *Resolver {
	if l != nil {
		r.logger = l
	}
	return r
}

// keyHeader is how a pipeline presents its credential.
const keyHeader = "Authorization"

// viaBrowser marks an arrival a browser made by itself, where no session of
// ours stands behind it.
//
// The trusted-header path is the case: the proxy authenticates from its own
// cookie, which the browser attaches without anybody asking, so a
// state-changing request needs the same forgery guard a session gets. There is
// no session row to hold an echoed value, so this session carries none and
// nothing can match it — a deployment on that path answers such requests only
// when it is told which origins it serves.
var viaBrowser = &Session{}

// FromBrowserWithoutSession reports whether this is such an arrival.
func FromBrowserWithoutSession(session *Session) bool { return session == viaBrowser }

// SessionCookie is what a browser holds after signing in. It carries the
// session token and nothing else — no identity, no roles, nothing a page could
// read and act on — and it is marked so that scripts cannot read it at all.
const SessionCookie = "openpsirt_session"

// CookieName is the name a browser actually holds, which carries a prefix
// wherever this deployment is served over TLS.
//
// `__Host-` is the only control that stops a sibling host writing a cookie
// this deployment then reads: a browser refuses to set a name with that prefix
// unless the cookie is Secure, path-wide and bound to exactly the host that
// set it — so `evil.internal.example` cannot plant one for
// `psirt.internal.example`, which is the premise every cookie-planting attack
// here rests on. Signing the value proves this deployment wrote it and not
// that it wrote it for *this* browser, so an attacker who can write cookies
// plants a validly-signed one of their own and the callback issues the
// victim's browser a session for the attacker's account.
//
// Cleared for a deployment running without TLS, where the prefix would make
// the browser drop the cookie and every request afterwards look like a
// stranger's — the same reason Secure is a parameter there.
func CookieName(name string, plainHTTP bool) string {
	if plainHTTP {
		return name
	}
	return "__Host-" + name
}

// CSRFHeader is where a page echoes the value bound to its session.
const CSRFHeader = "X-CSRF-Token"

// Resolve works out who is asking.
//
// One step for every sort of credential, so that what a request is allowed to
// do is decided in one place rather than in each handler that remembers to
// ask.
func (r *Resolver) Resolve(ctx context.Context, req *http.Request) (Subject, *Session, error) {
	// Every credential says which kind it is, so this dispatches rather than
	// trying each store in turn. Trying both would mean a pipeline's key could
	// be looked up as somebody's personal token, and would make the cost of a
	// wrong credential depend on which store happened to be asked first.
	if secret, ok := bearer(req.Header.Get(keyHeader)); ok {
		switch {
		case strings.HasPrefix(secret, TokenPrefix):
			subject, err := r.store.ResolveToken(ctx, secret)
			return subject, nil, err
		case strings.HasPrefix(secret, KeyPrefix):
			subject, err := r.store.ResolveKey(ctx, secret)
			return subject, nil, err
		}
		// Presented something, and it is not a shape we issue.
		return Subject{}, nil, ErrDenied
	}

	// The proxy is asked before the cookie, where one is configured. In that
	// arrangement the proxy is the authority on who is here and says so on
	// every request, while a cookie says who was here when it was issued —
	// so honoring the cookie first would let a stale one outrank a live
	// assertion about the same browser.
	if r.trust.Enabled() {
		identity := strings.TrimSpace(req.Header.Get(r.trust.Header))
		if identity == "" {
			return r.fromCookie(ctx, req)
		}
		if !r.trust.trusts(req.RemoteAddr) {
			// The header is present and this is not somewhere it is honored
			// from, which is either a misconfiguration or somebody reaching
			// past the proxy. Both are refusals, and the caller is told no
			// more than anybody else is.
			//
			// It is logged because the two are indistinguishable from the
			// outside and an operator who listed a proxy's address in one
			// family and is being reached from the other has no other way to
			// find out: the request simply fails, correctly, forever.
			r.logger.Warn("refused a trusted header presented from an untrusted source",
				"header", r.trust.Header, "source", req.RemoteAddr)
			return Subject{}, nil, ErrDenied
		}
		// The proxy reports membership too, where it is configured to.
		// This extends no trust that was not already extended: anybody
		// able to forge the group header could forge the username
		// header and claim to be an administrator outright.
		//
		// It has no stable identifier of its own — it asserts a username
		// on every request and there is nothing else to match on — so
		// the username decides and nothing is bound. Binding a made-up
		// identifier here would claim the identity against the provider,
		// and whichever path arrived first would lock the other out.
		who := Arrival{ViaProxy: true, Username: identity}
		if r.mode(ctx) == GroupBound {
			subject, err := r.store.AdmitByGroups(ctx, who, r.trust.groupsFrom(req))
			return subject, viaBrowser, err
		}
		person, err := r.store.MatchProxy(ctx, who.Username)
		if err != nil {
			return Subject{}, nil, ErrDenied
		}
		subject, err := r.store.Resolve(ctx, person.Identity)
		// Reported as a browser arrival with no session of ours behind it. The
		// proxy authenticates from a cookie the browser sends by itself, which
		// is precisely what makes a hostile page able to act as the signed-in
		// user — so this path needs the same guard a session gets, even though
		// there is no session row to bind a value to.
		return subject, viaBrowser, err
	}

	return r.fromCookie(ctx, req)
}

// fromCookie resolves a browser's session.
//
// The session is handed back alongside the subject because a request carrying
// one is a request a browser made by itself: the cookie is attached without
// anybody asking for it, which is exactly what makes cross-site request
// forgery possible and what the value bound to the session guards against .
// Nothing else needs to know which door a request came through.
func (r *Resolver) fromCookie(ctx context.Context, req *http.Request) (Subject, *Session, error) {
	cookie, err := req.Cookie(CookieName(SessionCookie, r.plainHTTP))
	if err != nil || cookie.Value == "" {
		return Subject{}, nil, ErrDenied
	}
	return r.store.ResolveSession(ctx, cookie.Value)
}

// bearer reads a presented credential.
func bearer(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):]), true
	}
	return "", false
}

// ParseSources reads the addresses a header is honored from.
//
// A bare address is taken as itself, so an operator naming one proxy does not
// have to write a mask to say so.
func ParseSources(raw string) ([]net.IPNet, error) {
	var out []net.IPNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			out = append(out, *network)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("%q is neither an address nor a range", entry)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

// Bootstrap grants administrator to the identities configuration names.
//
// Applied at every start rather than only the first, which makes it the
// documented way back in: an operator who has locked themselves out adds
// themselves and restarts. For software somebody else runs, a way back in
// matters more than a tidy one-shot bootstrap.
//
// It is a pre-authorization rather than a bypass. Being named grants the role;
// it does not admit anybody who has not authenticated.
func Bootstrap(ctx context.Context, store *Store, identities []string) error {
	return store.NameBootstrapAdmins(ctx, identities)
}
