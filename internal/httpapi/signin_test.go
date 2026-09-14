package httpapi_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/schema"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// stubProvider stands in for a real one, so the paths that decide who gets in
// can be tested without an identity provider to sign in to.
type stubProvider struct {
	says   *signin.Identity
	fail   error
	issuer string
}

func (s *stubProvider) Name() string { return "stub" }

// Issuer is who mints the identifiers, which is what an identity is recorded
// against. Distinct from the name here on purpose: the two being the same
// string is what hid a provider change from the startup check.
func (s *stubProvider) Issuer() string {
	if s.issuer != "" {
		return s.issuer
	}
	return "https://stub.example"
}

func (s *stubProvider) Begin(_ context.Context, _ string) (string, signin.Pending, error) {
	return "https://provider.example/authorize", signin.Pending{
		State: "the-state", Nonce: "the-nonce", Verifier: "the-verifier",
	}, nil
}

func (s *stubProvider) Complete(_ context.Context, _ string, _ signin.Pending, _ string) (*signin.Identity, error) {
	if s.fail != nil {
		return nil, s.fail
	}
	// Stamped here the way both real adapters stamp it, so a test standing on
	// this double stands on something that behaves like the boundary. An
	// identifier travels with the provider that issued it, because one
	// provider's identifier names somebody else at another.
	said := *s.says
	if said.Provider == "" {
		said.Provider = s.Issuer()
	}
	return &said, nil
}

// signInReach is a server with one provider and one person who was granted
// something.
type signInReach struct {
	handler  http.Handler
	provider *stubProvider
	rights   *access.Store
	// db is the same database the handler reads, so a test can change a
	// setting the sign-in path is supposed to obey.
	db *database.DB
}

// Most sign-in tests pin a redirect, a cookie or a refusal, not a query, and
// run on two engines; the one that pins what the identity table conflicts on
// runs on four. The rule is which tests run on which engines, at dbtest.Two.
func eachSignIn(t *testing.T, fn func(t *testing.T, r *signInReach)) {
	t.Helper()
	signInOn(t, dbtest.Each, fn)
}

func twoSignIn(t *testing.T, fn func(t *testing.T, r *signInReach)) {
	t.Helper()
	signInOn(t, dbtest.Two, fn)
}

func signInOn(t *testing.T, on engines, fn func(t *testing.T, r *signInReach)) {
	t.Helper()
	on(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		product, err := catalog.NewStore(db.DB).DeclareProduct(ctx, "mine", "Mine")
		if err != nil {
			t.Fatal(err)
		}
		rights := access.NewStore(db.DB)
		granted, err := rights.Ensure(ctx, "granted", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.Claim(ctx, granted.ID, "granted"); err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, granted.ID, product.ID, access.PublicRead); err != nil {
			t.Fatal(err)
		}
		// Somebody recorded and granted nothing, who must be refused exactly
		// as a stranger is.
		ungranted, err := rights.Ensure(ctx, "ungranted", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.Claim(ctx, ungranted.ID, "ungranted"); err != nil {
			t.Fatal(err)
		}

		provider := &stubProvider{says: &signin.Identity{Subject: "1", Username: "granted"}}
		handler, _ := httpapi.New(quiet, nil, httpapi.Ingest{
			DB: db, Queue: queue.New(db, queue.DefaultOptions()),
			// Plain HTTP, so the cookies keep their bare names: a browser
			// will not set a `__Host-` cookie without TLS, and a harness
			// that prefixed them here would be testing a shape no
			// deployment of this configuration has.
			Access:    access.NewResolver(rights, access.Trust{}).OverPlainHTTP(true),
			Providers: map[string]signin.Provider{"stub": provider},
			PlainHTTP: true,
			// Stated, because a provider compares the callback against what
			// it was registered with, so it cannot be taken from the request.
			BaseURL: "http://example.com",
		})
		fn(t, &signInReach{handler: handler, provider: provider, rights: rights, db: db})
	})
}

// callback is what the provider sends the browser back with.
func callback(t *testing.T, r *signInReach, state, code string, pending bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/sign-in/stub/callback?state="+state+"&code="+code, nil)
	if pending {
		// What begin would have left behind.
		start := httptest.NewRequest(http.MethodGet, "/v1/sign-in/stub", nil)
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, start)
		for _, cookie := range rec.Result().Cookies() {
			req.AddCookie(cookie)
		}
	}
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

func TestSigningInSendsTheBrowserToTheProvider(t *testing.T) {
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		req := httptest.NewRequest(http.MethodGet, "/v1/sign-in/stub", nil)
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("starting a sign-in answered %d, want 302", rec.Code)
		}
		if where := rec.Header().Get("Location"); !strings.HasPrefix(where, "https://provider.example/") {
			t.Errorf("sent the browser to %q", where)
		}
		// What has to survive the round trip is left with the browser, and
		// left where a script cannot read it.
		var held *http.Cookie
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == "openpsirt_pending" {
				held = cookie
			}
		}
		if held == nil {
			t.Fatal("nothing was remembered for the round trip")
		}
		if !held.HttpOnly {
			t.Error("what the sign-in remembered is readable by script")
		}
		if held.Value == "" || strings.Contains(held.Value, "the-verifier") {
			t.Errorf("the proof-key secret is sitting in the clear: %q", held.Value)
		}
	})
}

func TestAProviderNobodyConfiguredIsNotThere(t *testing.T) {
	// The same answer a name that was never a provider gets, so guessing does
	// not enumerate which are in use.
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		for _, path := range []string{"/v1/sign-in/github", "/v1/sign-in/okta", "/v1/sign-in/okta/callback"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			r.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s answered %d, want 404", path, rec.Code)
			}
		}
	})
}

func TestACallbackWithoutTheSignInThatStartedItIsRefused(t *testing.T) {
	// The state is what stops somebody handing a signed-in person a callback
	// of their own making and having the session come back as theirs.
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		for _, c := range []struct {
			what    string
			state   string
			code    string
			pending bool
		}{
			{"no sign-in in progress", "the-state", "a-code", false},
			{"a state that was never sent", "somebody-elses-state", "a-code", true},
			{"no state at all", "", "a-code", true},
			{"no code", "the-state", "", true},
		} {
			rec := callback(t, r, c.state, c.code, c.pending)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("a callback with %s answered %d, want 401", c.what, rec.Code)
			}
			if cookies := rec.Result().Cookies(); hasSession(cookies) {
				t.Errorf("a callback with %s handed out a session", c.what)
			}
		}
	})
}

func TestSomebodyWhoAuthenticatesButWasGrantedNothingGetsInNowhere(t *testing.T) {
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		// A distinct subject each time. Reusing one made the second case match
		// the first person by their pinned identifier and rename them, so the
		// stranger path was never reached and the test quietly demonstrated
		// identity mutation while claiming to test refusal.
		for i, who := range []string{"ungranted", "a-stranger"} {
			r.provider.says = &signin.Identity{Subject: fmt.Sprintf("subject-%d", i+2), Username: who}
			rec := callback(t, r, "the-state", "a-code", true)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%q answered %d, want 401", who, rec.Code)
			}
			if hasSession(rec.Result().Cookies()) {
				t.Errorf("%q was handed a session", who)
			}
		}
	})
}

func TestAuthenticatingCreatesNobodyOnASignInPath(t *testing.T) {
	// Access is granted in advance or not at all. A sign-in path that records
	// somebody is a sign-in path that admits whoever the provider vouches for.
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		r.provider.says = &signin.Identity{Subject: "3", Username: "a-stranger"}
		callback(t, r, "the-state", "a-code", true)

		if _, err := r.rights.ByIdentity(t.Context(), "a-stranger"); err == nil {
			t.Error("signing in recorded somebody nobody had granted anything")
		}
	})
}

func TestSigningInGrantsTheSessionSomebodyWasAlreadyOwed(t *testing.T) {
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		rec := callback(t, r, "the-state", "a-code", true)
		if rec.Code != http.StatusFound {
			t.Fatalf("signing in answered %d, want 302: %s", rec.Code, rec.Body.String())
		}

		cookies := rec.Result().Cookies()
		if !hasSession(cookies) {
			t.Fatal("signing in handed out no session")
		}
		for _, cookie := range cookies {
			switch cookie.Name {
			case access.SessionCookie:
				if !cookie.HttpOnly {
					t.Error("the session cookie is readable by script")
				}
			case "openpsirt_csrf":
				if cookie.HttpOnly {
					t.Error("the value a page has to echo cannot be read by the page")
				}
			}
		}

		// And it works.
		req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		reading := httptest.NewRecorder()
		r.handler.ServeHTTP(reading, req)
		if reading.Code != http.StatusOK {
			t.Errorf("the session handed out did not work: %d", reading.Code)
		}
	})
}

func TestAProviderThatFailedSaysNothingAboutWhy(t *testing.T) {
	// What went wrong between us and a provider is an operator's problem.
	// Describing it to whoever is at the browser describes our configuration.
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		r.provider.fail = errClientSecretRejected
		rec := callback(t, r, "the-state", "a-code", true)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("a failed exchange answered %d, want 401", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("the refusal described the fault: %q", rec.Body.String())
		}
	})
}

func hasSession(cookies []*http.Cookie) bool {
	for _, cookie := range cookies {
		if cookie.Name == access.SessionCookie && cookie.Value != "" {
			return true
		}
	}
	return false
}

// errClientSecretRejected stands for the sort of fault a provider reports:
// specific, useful to an operator, and nobody else's business.
var errClientSecretRejected = errors.New("the client secret was rejected")

func TestAnIdentifierAlreadyPinnedIsNotRedeemableByAnotherName(t *testing.T) {
	// The property the reused-subject test was standing on without checking.
	// Somebody whose identifier is pinned is that person whatever name the
	// provider now reports, and a different identifier reporting a pinned
	// name is somebody else.
	eachSignIn(t, func(t *testing.T, r *signInReach) {
		r.provider.says = &signin.Identity{Subject: "1001", Username: "granted"}
		if rec := callback(t, r, "the-state", "a-code", true); rec.Code != http.StatusFound {
			t.Fatalf("the authorized person could not sign in: %d", rec.Code)
		}

		// Somebody else, presenting the name that person signs in under.
		r.provider.says = &signin.Identity{Subject: "2002", Username: "granted"}
		if rec := callback(t, r, "the-state", "a-code", true); rec.Code != http.StatusUnauthorized {
			t.Errorf("somebody else redeemed a pinned name: %d", rec.Code)
		}

		// And the original, renamed, is still themselves.
		r.provider.says = &signin.Identity{Subject: "1001", Username: "granted-elsewhere"}
		if rec := callback(t, r, "the-state", "a-code", true); rec.Code != http.StatusFound {
			t.Errorf("a rename locked somebody out of their own account: %d", rec.Code)
		}
	})
}

func TestAnIdentityTokenNamingNobodyIsRefused(t *testing.T) {
	// A provider that verifies but names no subject leaves nothing stable to
	// match on, which would quietly reduce this deployment to matching by
	// name — the thing the pinning exists to replace.
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		r.provider.says = &signin.Identity{Subject: "", Username: "granted"}
		if rec := callback(t, r, "the-state", "a-code", true); rec.Code != http.StatusUnauthorized {
			t.Errorf("a sign-in naming no subject answered %d, want 401", rec.Code)
		}
	})
}

func TestHowLongASignInLastsIsTheSettingAnAdministratorChanged(t *testing.T) {
	// The setting is offered on the administration screen, so it has to be the
	// one that decides. It was offered and read by nothing for a while, and a
	// value somebody sets that changes nothing is worse than not offering it.
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		const chosen = 90 * time.Minute
		if err := setting.NewStore(r.db.DB).Set(t.Context(),
			setting.SessionLifetime, chosen.String()); err != nil {
			t.Fatal(err)
		}

		rec := callback(t, r, "the-state", "a-code", true)
		if rec.Code != http.StatusFound {
			t.Fatalf("signing in answered %d: %s", rec.Code, rec.Body.String())
		}

		var sessions []struct {
			ExpiresAt time.Time `bun:"expires_at"`
		}
		if err := r.db.DB.NewSelect().Table("session").
			ColumnExpr("expires_at").Scan(t.Context(), &sessions); err != nil {
			t.Fatal(err)
		}
		if len(sessions) != 1 {
			t.Fatalf("%d sessions were started, want 1", len(sessions))
		}
		// Against the default rather than against an exact instant: what is
		// being tested is that the setting decided, not the clock.
		lasts := time.Until(sessions[0].ExpiresAt)
		if lasts > 2*chosen || lasts >= access.DefaultSessionLifetime {
			t.Errorf("the session lasts %v, want about %v — the setting was not read",
				lasts.Round(time.Minute), chosen)
		}
	})
}

// signedInFrom runs a whole sign-in that began at one address, and returns
// where the browser is sent afterwards.
func signedInFrom(t *testing.T, r *signInReach, began string) string {
	t.Helper()
	start := httptest.NewRequest(http.MethodGet, "/v1/sign-in/stub"+began, nil)
	started := httptest.NewRecorder()
	r.handler.ServeHTTP(started, start)
	if started.Code != http.StatusFound {
		t.Fatalf("starting a sign-in answered %d", started.Code)
	}

	back := httptest.NewRequest(http.MethodGet, "/v1/sign-in/stub/callback?state=the-state&code=a-code", nil)
	for _, cookie := range started.Result().Cookies() {
		back.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, back)
	if rec.Code != http.StatusFound {
		t.Fatalf("completing a sign-in answered %d, want 302: %s", rec.Code, rec.Body.String())
	}
	return rec.Header().Get("Location")
}

func TestSigningInComesBackToWhereSomebodyWas(t *testing.T) {
	// A session ends while somebody is halfway through a justification.
	// The text survives, because a draft is written as it is typed — but a
	// sign-in that always lands on the home page still makes them find
	// their way back to the screen they were on, which for a long piece of
	// reasoning is the difference between carrying on and starting again .
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		where := signedInFrom(t, r,
			"?return=%2Fproducts%2Fsonic%2Fstreams%2Fmaster%2Fvariants%2Fbroadcom%2Ffindings")
		if where != "/products/sonic/streams/master/variants/broadcom/findings" {
			t.Errorf("a sign-in that began on a findings list landed on %q", where)
		}

		// And a sign-in that began nowhere in particular still lands home, so
		// the address is an addition rather than a requirement.
		if home := signedInFrom(t, r, ""); home != "/" {
			t.Errorf("a sign-in with no address landed on %q, want /", home)
		}
	})
}

func TestASignInWillNotSendABrowserOffThisDeployment(t *testing.T) {
	// The classic bug in exactly this flow: a sign-in that sends a browser
	// wherever a parameter says makes this deployment's own domain vouch for
	// somebody else's page. Everything that is not a path here becomes the
	// home page — refusing to sign somebody in over it would punish the person
	// for a link somebody else wrote.
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		for _, hostile := range []struct {
			what  string
			given string
		}{
			{"an absolute address", "https%3A%2F%2Felsewhere.example%2Fpage"},
			{"a protocol-relative address", "%2F%2Felsewhere.example%2Fpage"},
			{"a backslash browsers read as protocol-relative", "%2F%5Celsewhere.example%2Fpage"},
			{"a scheme with no host", "javascript%3Aalert(1)"},
			{"a bare host", "elsewhere.example"},
			{"a relative path that climbs out", "..%2F..%2Fsomewhere"},
			{"an address with a host and a leading slash", "%2F%2Fuser%40elsewhere.example%2F"},
		} {
			where := signedInFrom(t, r, "?return="+hostile.given)
			if where != "/" {
				t.Errorf("%s (%s) sent the browser to %q, want /",
					hostile.what, hostile.given, where)
			}
		}
	})
}

// A sign-in this deployment did not start is not a sign-in.
//
// The cookie holding the state was unsigned, and the callback compared the
// state it was given against the state in that cookie — so somebody who can
// write a cookie on this host could start a sign-in of their own, plant its
// state and verifier in a victim's browser, and have the callback hand that
// browser a session for the attacker's account. A comparison against a value
// the other party authored is not a control.
func TestASignInNobodyStartedHereIsRefused(t *testing.T) {
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		forged, err := json.Marshal(map[string]any{
			"pending": map[string]string{
				"State": "the-state", "Nonce": "the-nonce", "Verifier": "the-verifier",
			},
			"return": "/",
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet,
			"/v1/sign-in/stub/callback?state=the-state&code=a-code", nil)
		// Set as a header rather than built as a cookie value: a browser sends
		// a name and a value and nothing else, so this is what a planted
		// request actually looks like on the wire.
		req.Header.Set("Cookie",
			"openpsirt_pending="+base64.RawURLEncoding.EncodeToString(forged))
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)

		if rec.Code == http.StatusFound {
			t.Fatalf("a sign-in nobody started here completed: %s",
				rec.Header().Get("Location"))
		}
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == "openpsirt_session" && cookie.Value != "" {
				t.Error("a planted sign-in was issued a session")
			}
		}
	})
}

func TestATamperedReturnAddressIsStillRefused(t *testing.T) {
	// The address is checked on the way in and again on the way out. The
	// cookie holding it is the browser's own, so somebody may edit it — and
	// while a person redirecting themselves gains nothing, an address that
	// left here is an address this deployment sent, which is what an open
	// redirect is.
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		// What begin would have left behind, with the address replaced —
		// signed with this deployment's own key, because an unsigned one is
		// refused before the address is looked at.
		forged, err := json.Marshal(map[string]any{
			"pending": map[string]string{
				"State": "the-state", "Nonce": "the-nonce", "Verifier": "the-verifier",
			},
			"return": "https://elsewhere.example/page",
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet,
			"/v1/sign-in/stub/callback?state=the-state&code=a-code", nil)
		req.Header.Set("Cookie", "openpsirt_pending="+r.sealed(t, forged))
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("completing a sign-in answered %d, want 302: %s", rec.Code, rec.Body.String())
		}
		if where := rec.Header().Get("Location"); where != "/" {
			t.Errorf("a tampered address sent the browser to %q, want /", where)
		}
	})
}

// sealed signs a pending payload the way the sign-in path does, so a test can
// hand the callback something this deployment would accept.
func (r *signInReach) sealed(t *testing.T, payload []byte) string {
	t.Helper()
	// Minted on first use, so a sign-in is started to bring it into being.
	begin := httptest.NewRequest(http.MethodGet, "/v1/sign-in/stub", nil)
	r.handler.ServeHTTP(httptest.NewRecorder(), begin)

	held, found, err := setting.NewStore(r.db.DB).Get(t.Context(), setting.SignInKey)
	if err != nil || !found {
		t.Fatalf("this deployment has no sign-in key: %v %v", found, err)
	}
	key, err := base64.RawURLEncoding.DecodeString(held)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// A validly-signed pending cookie from somebody else's sign-in is still
// somebody else's sign-in.
//
// The signature says this deployment authored the value. It does not say this
// deployment authored it for *this* browser — so an attacker who can write a
// cookie on the host starts a sign-in of their own, takes the signed pending
// value handed back, plants it in a victim's browser, and the callback issues
// that browser a session for the attacker's account. Every earlier test here
// presented an unsigned forgery, which the signature alone already refused.
//
// What denies a sibling host the write is the `__Host-` cookie prefix, which
// this harness runs without because it serves plain HTTP. So what is asserted
// here is the half a name cannot carry: the session that comes back is the one
// the pending value was minted for, and never the victim's.
func TestASignedPendingCookieFromAnotherSignInIsNotYours(t *testing.T) {
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		// The attacker's own sign-in, which hands back a properly signed
		// pending cookie.
		begun := httptest.NewRecorder()
		r.handler.ServeHTTP(begun, httptest.NewRequest(http.MethodGet, "/v1/sign-in/stub", nil))
		if begun.Code != http.StatusFound {
			t.Fatalf("beginning a sign-in answered %d: %s", begun.Code, begun.Body.String())
		}
		var planted *http.Cookie
		for _, cookie := range begun.Result().Cookies() {
			if cookie.Name == "openpsirt_pending" && cookie.Value != "" {
				planted = cookie
			}
		}
		if planted == nil {
			t.Fatal("beginning a sign-in left no pending cookie, so this tests nothing")
		}
		// The state the provider will echo, which the attacker knows because
		// they started this sign-in. The stub answers with a fixed one.
		const state = "the-state"

		// Planted in the victim's browser, which then completes it.
		req := httptest.NewRequest(http.MethodGet,
			"/v1/sign-in/stub/callback?state="+state+"&code=a-code", nil)
		req.AddCookie(planted)
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)

		// It completes — the signature is genuine and the state matches,
		// because both are the attacker's own. What the browser is handed is
		// a session for whoever the provider says signed in, which is the
		// attacker: the victim's own account is never reached, and the
		// prefix is what stops the cookie being planted at all where this
		// deployment is served over TLS.
		if rec.Code != http.StatusFound {
			t.Fatalf("completing the planted sign-in answered %d: %s", rec.Code, rec.Body.String())
		}
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name != access.CookieName(access.SessionCookie, true) || cookie.Value == "" {
				continue
			}
			who, _, err := r.rights.ResolveSession(t.Context(), cookie.Value)
			if err != nil {
				t.Fatal(err)
			}
			if who.Identity != "granted" {
				t.Errorf("the session handed to the browser is %q", who.Identity)
			}
		}
	})
}

// The name a browser is asked to hold carries the prefix wherever this
// deployment is served over TLS, which is the control that denies a sibling
// host the write in the first place.
func TestTheCookiesABrowserHoldsAreBoundToThisHost(t *testing.T) {
	for _, each := range []struct {
		name  string
		plain bool
		want  string
	}{
		{access.SessionCookie, false, "__Host-openpsirt_session"},
		{access.SessionCookie, true, "openpsirt_session"},
		{"openpsirt_pending", false, "__Host-openpsirt_pending"},
		{"openpsirt_csrf", false, "__Host-openpsirt_csrf"},
	} {
		if got := access.CookieName(each.name, each.plain); got != each.want {
			t.Errorf("over plain=%v, %q is held as %q, want %q",
				each.plain, each.name, got, each.want)
		}
	}
}
