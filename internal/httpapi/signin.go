package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// pendingCookie holds what a sign-in has to remember while the browser is away
// at the provider.
//
// Held by the browser rather than here, and signed with this deployment's own
// key so that what comes back is what went out. The alternative is a table of
// half-finished sign-ins, which has to be swept and which anybody can fill by
// starting sign-ins they never come back from.
const pendingCookie = "openpsirt_pending"

// pendingLife bounds how long a sign-in may take.
//
// Long enough to type a password and answer a second factor, short enough that
// an abandoned sign-in is not still usable later. Nothing is signed in during
// this window: what the cookie holds is the makings of a sign-in, not one.
const pendingLife = 10 * time.Minute

// registerSignIn mounts the sign-in paths on the router directly rather than
// through the API description.
//
// They are browser redirects rather than API operations: nothing calls them
// with a client, the response is a 302 with cookies, and describing them as
// operations would put two routes in the document that no generated client
// could ever usefully call.
func registerSignIn(router chi.Router, in Ingest) {
	if len(in.Providers) == 0 {
		return
	}
	router.Get("/v1/sign-in/{provider}", func(w http.ResponseWriter, r *http.Request) {
		begin(w, r, in)
	})
	router.Get("/v1/sign-in/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		complete(w, r, in)
	})
}

// begin sends the browser to the provider.
func begin(w http.ResponseWriter, r *http.Request, in Ingest) {
	provider, ok := in.Providers[chi.URLParam(r, "provider")]
	if !ok {
		// The same answer a provider nobody configured gets, so that guessing
		// names does not enumerate which are in use.
		Problem(w, http.StatusNotFound, "no such sign-in provider")
		return
	}

	callback, err := in.redirectURI(r, provider.Name())
	if err != nil {
		wentWrongHere(w, in, "a sign-in could not be started", err)
		return
	}
	where, pending, err := provider.Begin(r.Context(), callback)
	if err != nil {
		wentWrongHere(w, in, "a sign-in could not be started", err)
		return
	}

	encoded, err := json.Marshal(inProgress{
		Pending: pending,
		// Where to land afterwards, carried in our own cookie rather than
		// through the provider. It never leaves this browser, so nothing a
		// provider echoes back can decide where somebody ends up.
		Return: aLocalPath(r.URL.Query().Get("return")),
	})
	if err != nil {
		wentWrongHere(w, in, "a sign-in could not be started", err)
		return
	}
	sealed, err := sealPending(r.Context(), in, encoded)
	if err != nil {
		wentWrongHere(w, in, "a sign-in could not be started", err)
		return
	}
	cookie := browserCookie(pendingCookie, sealed, false, in.PlainHTTP,
		int(pendingLife.Seconds()))
	http.SetCookie(w, &cookie)
	// Where this goes is the provider's authorization endpoint, and an adapter
	// refuses at startup to be built around one that is not on the configured
	// provider's own host. That check is there rather than here because a
	// provider that would misdirect people should stop the process, not
	// misdirect the first person to sign in.
	http.Redirect(w, r, where, http.StatusFound) //nolint:gosec // G710: the target is a provider endpoint validated against its configured issuer at startup.
}

// complete turns what the provider sent back into a session.
func complete(w http.ResponseWriter, r *http.Request, in Ingest) {
	provider, ok := in.Providers[chi.URLParam(r, "provider")]
	if !ok {
		Problem(w, http.StatusNotFound, "no such sign-in provider")
		return
	}

	held, err := pendingFrom(r.Context(), in, r)
	if err != nil {
		refuseSignIn(w, in)
		return
	}
	pending := held.Pending
	// Compared before anything is exchanged. The state is what stops somebody
	// handing a signed-in person a callback of their own making and having the
	// session come back as theirs.
	if state := r.URL.Query().Get("state"); state == "" || state != pending.State {
		refuseSignIn(w, in)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		refuseSignIn(w, in)
		return
	}

	callback, err := in.redirectURI(r, provider.Name())
	if err != nil {
		wentWrongHere(w, in, "a sign-in could not be completed", err)
		return
	}
	identity, err := provider.Complete(r.Context(), code, pending, callback)
	if err != nil {
		// Logged rather than described. What went wrong between us and a
		// provider is an operator's problem, and telling whoever is at the
		// browser would describe our configuration to them.
		if in.Logger != nil {
			in.Logger.Warn("a sign-in could not be completed",
				"provider", provider.Name(), "error", err)
		}
		refuseSignIn(w, in)
		return
	}

	if in.DB == nil {
		refuseSignIn(w, in)
		return
	}
	rights := access.NewStore(in.DB.DB)

	// Authenticating is not being authorized, and which of the two
	// questions gets asked here depends on where this deployment says
	// roles come from.
	//
	// Assigned: this looks somebody up and cannot bring them into being, so
	// somebody who signs in perfectly well and was never granted anything is
	// refused.
	//
	// Derived: the mapping an administrator made *is* the advance
	// authorization, so somebody arriving for the first time in a mapped group
	// is admitted and recorded then — and somebody in no mapped group is
	// refused exactly as a stranger is.
	person, err := admit(r, in, rights, provider.Name(), identity)
	if err != nil {
		if in.Logger != nil {
			in.Logger.Info("refused somebody who authenticated but reaches nothing",
				"provider", provider.Name(), "identity", identity.Username)
		}
		refuseSignIn(w, in)
		return
	}

	// The administrator's setting first, then whatever the deployment was
	// started with, then the built-in. The setting is offered on the
	// administration screen, so it has to be the one that decides — a value
	// somebody sets there and nothing reads is worse than not offering it.
	lifetime := access.DefaultSessionLifetime
	if in.SessionLifetime > 0 {
		lifetime = in.SessionLifetime
	}
	if in.DB != nil {
		chosen, err := setting.NewStore(in.DB.DB).Duration(r.Context(), setting.SessionLifetime, lifetime)
		if err != nil {
			wentWrongHere(w, in, "how long a sign-in lasts could not be read", err)
			return
		}
		lifetime = chosen
	}
	issued, err := rights.StartSession(r.Context(), person.ID, lifetime)
	if err != nil {
		wentWrongHere(w, in, "a session could not be started", err)
		return
	}

	session := SessionCookie(issued.Token, in.PlainHTTP)
	csrf := CSRFCookie(issued.CSRF, in.PlainHTTP)
	cleared := browserCookie(pendingCookie, "", false, in.PlainHTTP, -1)
	http.SetCookie(w, &session)
	http.SetCookie(w, &csrf)
	http.SetCookie(w, &cleared)
	// Back to what they were doing, where they were doing something. A
	// sign-in that always lands on the home page loses somebody's place
	// every time a session ends, which for a long justification is the
	// difference between carrying on and starting again.
	where := held.Return
	if where == "" {
		where = "/"
	}
	http.Redirect(w, r, where, http.StatusFound)
}

// admit decides whether somebody who authenticated may be here, in whichever
// way this deployment assigns roles.
func admit(r *http.Request, in Ingest, rights *access.Store, provider string, identity *signin.Identity) (*access.Account, error) {
	// Matched on the provider's own stable identifier, with the username only
	// redeeming an authorization nobody has pinned yet. A username moves —
	// people rename themselves, and a forge login left behind can be taken by
	// somebody else — so matching on it would eventually hand one person's
	// access to another.
	who := access.Arrival{
		Provider: provider, Subject: identity.Subject,
		Username: identity.Username, DisplayName: identity.DisplayName,
	}

	if in.Mode != nil && in.Mode(r.Context()) == access.GroupBound {
		if _, err := rights.AdmitByGroups(r.Context(), who, identity.Groups); err != nil {
			return nil, err
		}
		return rights.MatchProvider(r.Context(), who.Provider, who.Subject, who.Username)
	}

	person, err := rights.MatchProvider(r.Context(), who.Provider, who.Subject, who.Username)
	if err != nil {
		return nil, err
	}
	if _, err := rights.Resolve(r.Context(), person.Identity); err != nil {
		return nil, err
	}
	fillEmail(r, in, rights, person, identity)
	return person, nil
}

// fillEmail takes an address from the provider, where it gave one and nobody
// here has recorded one.
//
// Only where the provider says it verified the address, which is the same
// caution the username fallback already takes: an unverified one is whatever
// the account holder typed, and mail sent to it is mail sent wherever they
// said — which for an alert about an undisclosed finding is the disclosure the
// alert exists to avoid. Each adapter decides what verified means for its
// provider and says so rather than handing over an address and leaving the
// question open.
//
// A failure here does not fail the sign-in. Somebody arriving and being let in
// is the thing that was asked for; where to reach them later is not part of
// it, and refusing the first because the second did not work would lock people
// out over a column.
func fillEmail(r *http.Request, in Ingest, rights *access.Store,
	person *access.Account, identity *signin.Identity,
) {
	if !identity.EmailVerified || strings.TrimSpace(identity.Email) == "" {
		return
	}
	if err := rights.SetEmail(r.Context(), person.ID, identity.Email, access.FromProvider); err != nil && in.Logger != nil {
		in.Logger.Warn("could not record where to reach somebody who signed in",
			"person", person.Identity, "error", err)
	}
}

// pendingFrom reads back what the sign-in remembered.
//
// **Named so a sibling host cannot write it.** Over TLS the cookie carries the
// `__Host-` prefix, which a browser refuses to set unless the cookie is
// Secure, path-wide and bound to exactly the host that set it — so
// `evil.internal.example` cannot plant one for `psirt.internal.example`, which
// is the premise the attack rests on.
//
// **Signed as well, because the two answer different questions.** The
// signature says this deployment authored the value; the prefix says it
// authored it for *this* browser. Signing alone is not the control: an
// attacker who can write a cookie starts a sign-in of their own, takes the
// validly-signed pending value it hands back, plants that, and the callback
// issues the victim's browser a session for the attacker's account.
func pendingFrom(ctx context.Context, in Ingest, r *http.Request) (inProgress, error) {
	cookie, err := r.Cookie(access.CookieName(pendingCookie, in.PlainHTTP))
	if err != nil || cookie.Value == "" {
		return inProgress{}, errors.New("no sign-in is in progress")
	}
	raw, err := openPending(ctx, in, cookie.Value)
	if err != nil {
		return inProgress{}, err
	}
	var held inProgress
	if err := json.Unmarshal(raw, &held); err != nil {
		return inProgress{}, err
	}
	if held.Pending.State == "" || held.Pending.Verifier == "" {
		return inProgress{}, errors.New("the sign-in in progress is incomplete")
	}
	// Checked again on the way out as well as on the way in. The cookie is the
	// browser's, so somebody may edit it — and while a person redirecting
	// themselves somewhere gains nothing, an address that left here is an
	// address this deployment sent, which is the thing an open redirect is
	// about.
	held.Return = aLocalPath(held.Return)
	return held, nil
}

// sealPending signs what a sign-in leaves in the browser, and openPending
// refuses anything this deployment did not sign.
//
// The value stays in the cookie rather than moving to a row keyed by an
// opaque one: what it holds is short-lived, meaningless to anybody else, and
// needed by whichever replica the callback lands on — so the thing that has
// to be shared is a key rather than a table and a sweep.
func sealPending(ctx context.Context, in Ingest, payload []byte) (string, error) {
	key, err := signingKey(ctx, in)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func openPending(ctx context.Context, in Ingest, value string) ([]byte, error) {
	body, signature, found := strings.Cut(value, ".")
	if !found {
		return nil, errors.New("the sign-in in progress is not signed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, err
	}
	given, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}
	key, err := signingKey(ctx, in)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	// Constant time, like every other secret comparison here.
	if !hmac.Equal(mac.Sum(nil), given) {
		return nil, errors.New("the sign-in in progress was not started here")
	}
	return payload, nil
}

// signingKey is this deployment's own key, minted the first time it is
// wanted.
//
// Stored rather than held in memory because it has to be the same on every
// replica and across a restart: a sign-in begun on one process is finished by
// whichever answers the callback, and a key per process would refuse half of
// them for no reason a person could act on.
func signingKey(ctx context.Context, in Ingest) ([]byte, error) {
	if in.DB == nil {
		return nil, errors.New("no database, so a sign-in cannot be signed")
	}
	settings := setting.NewStore(in.DB.DB)
	held, found, err := settings.Get(ctx, setting.SignInKey)
	if err != nil {
		return nil, err
	}
	if found && held != "" {
		return base64.RawURLEncoding.DecodeString(held)
	}
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}
	minted := base64.RawURLEncoding.EncodeToString(fresh)
	if err := settings.Set(ctx, setting.SignInKey, minted); err != nil {
		return nil, err
	}
	// Read back, so two processes minting at once agree on which key won
	// rather than each signing with its own.
	stored, found, err := settings.Get(ctx, setting.SignInKey)
	if err != nil || !found {
		return fresh, err
	}
	return base64.RawURLEncoding.DecodeString(stored)
}

// inProgress is a sign-in that has been started: what the provider needs to
// finish it, and where the person was when they began.
type inProgress struct {
	Pending signin.Pending `json:"pending"`
	Return  string         `json:"return,omitempty"`
}

// aLocalPath keeps a return address that names somewhere on this deployment,
// and nothing else.
//
// **The whole of the open-redirect defense.** A sign-in that will send a
// browser wherever a parameter says is a way to make this deployment's own
// domain vouch for somebody else's page, and it is the classic bug in exactly
// this flow. So the address is a path here or it is discarded:
//
//   - it starts with a single "/", so no scheme and no host;
//   - it does not start with "//" or "/", which browsers read as
//     protocol-relative and would send the browser to another host;
//   - it parses, and carries no scheme or host of its own.
//
// Anything else becomes the home page, which is where a sign-in used to land
// unconditionally. Refusing to sign somebody in over it would punish the
// person for a link somebody else wrote.
func aLocalPath(where string) string {
	if where == "" || !strings.HasPrefix(where, "/") {
		return ""
	}
	if strings.HasPrefix(where, "//") || strings.HasPrefix(where, `/\`) {
		return ""
	}
	parsed, err := url.Parse(where)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return ""
	}
	return parsed.RequestURI()
}

// redirectURI is where the provider sends the browser back to.
//
// Built from the configured base address where there is one. A provider
// compares this against what it was registered with, so it has to be the
// address people actually arrive on rather than whatever this process thinks
// it is called — behind a proxy those differ.
func (in Ingest) redirectURI(r *http.Request, provider string) (string, error) {
	base := strings.TrimSuffix(in.BaseURL, "/")
	if base == "" {
		// The Host header is whatever the caller sent. Building the address a
		// provider will send somebody back to out of it means a request
		// claiming another host produces an authorization URL pointing there,
		// and whether that is exploitable depends entirely on how strictly the
		// provider matches its registered addresses — which is not ours to
		// assume.
		//
		// So a deployment that configured a provider has to say where it is
		// served. It is one setting, it is already needed for the provider's
		// own registration to match, and failing here is visible where the
		// alternative is not.
		return "", errors.New("this deployment has not been told the address it is served on")
	}
	return base + "/v1/sign-in/" + provider + "/callback", nil
}

// refuseSignIn answers a sign-in that will not be completed.
//
// One answer for every reason: a provider that failed, a state that did not
// match, somebody unknown, and somebody known but granted nothing. Telling
// them apart says whether a name is real, which is free reconnaissance for
// somebody who has just proved nothing.
func refuseSignIn(w http.ResponseWriter, in Ingest) {
	cleared := browserCookie(pendingCookie, "", false, in.PlainHTTP, -1)
	http.SetCookie(w, &cleared)
	Problem(w, http.StatusUnauthorized, "not authorized")
}

// wentWrongHere records a fault where an operator can read it and says nothing
// about it to whoever asked.
func wentWrongHere(w http.ResponseWriter, in Ingest, what string, err error) {
	if in.Logger != nil {
		in.Logger.Error(what, "error", err)
	}
	Problem(w, http.StatusInternalServerError, "something went wrong")
}
