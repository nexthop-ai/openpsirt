package httpapi_test

import (
	"context"
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
	says *signin.Identity
	fail error
}

func (s *stubProvider) Name() string { return "stub" }

func (s *stubProvider) Begin(_ context.Context, _ string) (string, signin.Pending, error) {
	return "https://provider.example/authorize", signin.Pending{
		State: "the-state", Nonce: "the-nonce", Verifier: "the-verifier",
	}, nil
}

func (s *stubProvider) Complete(_ context.Context, _ string, _ signin.Pending, _ string) (*signin.Identity, error) {
	if s.fail != nil {
		return nil, s.fail
	}
	return s.says, nil
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
		if err := rights.Claim(ctx, granted.ID, "stub", "granted"); err != nil {
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
		if err := rights.Claim(ctx, ungranted.ID, "stub", "ungranted"); err != nil {
			t.Fatal(err)
		}

		provider := &stubProvider{says: &signin.Identity{Subject: "1", Username: "granted"}}
		handler, _ := httpapi.New(quiet, nil, httpapi.Ingest{
			DB: db, Queue: queue.New(db, queue.DefaultOptions()),
			Access:    access.NewResolver(rights, access.Trust{}),
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

func TestATamperedReturnAddressIsStillRefused(t *testing.T) {
	// The address is checked on the way in and again on the way out. The
	// cookie holding it is the browser's own, so somebody may edit it — and
	// while a person redirecting themselves gains nothing, an address that
	// left here is an address this deployment sent, which is what an open
	// redirect is.
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		// What begin would have left behind, with the address replaced.
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
		// Set as a header rather than built as a cookie value: a browser sends
		// a name and a value and nothing else, so this is what a tampered
		// request actually looks like on the wire.
		req.Header.Set("Cookie",
			"openpsirt_pending="+base64.RawURLEncoding.EncodeToString(forged))
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
