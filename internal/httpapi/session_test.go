package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// asBrowser makes a request the way a signed-in browser does: the cookie goes
// by itself, and anything that changes something has to echo the value bound
// to the session.
func asBrowser(t *testing.T, r *reach, issued *access.Issued, method, path, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, declaredBody(method, path, "declared-in-a-browser"))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	// A cookie on the way *to* a server carries a name and a value and
	// nothing else: Secure, HttpOnly and SameSite are instructions a server
	// gives a browser, and mean nothing on a request.
	// Under the name a browser actually holds, which carries the prefix
	// that stops a sibling host writing one.
	req.AddCookie(&http.Cookie{ //nolint:gosec // a request cookie carries no attributes
		Name: access.CookieName(access.SessionCookie, false), Value: issued.Token,
	})
	if csrf != "" {
		req.Header.Set(access.CSRFHeader, csrf)
	}
	req.Header.Set("Origin", "http://"+req.Host)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

// signIn issues a session for somebody the fixture already granted something.
func signIn(t *testing.T, r *reach, identity string) *access.Issued {
	t.Helper()
	person, err := r.rights.ByIdentity(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := r.rights.StartSession(t.Context(), person.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func TestABrowserIsRecognizedByItsSessionAlone(t *testing.T) {
	// No header, no key. The cookie is the whole credential, which is what a
	// deployment with a real identity provider looks like.
	twoReach(t, func(t *testing.T, r *reach) {
		issued := signIn(t, r, "reader")
		if got := asBrowser(t, r, issued, http.MethodGet, "/v1/products", "").Code; got != http.StatusOK {
			t.Errorf("a signed-in browser reading products answered %d, want 200", got)
		}
	})
}

func TestAWriteFromABrowserHasToProveItCameFromOurOwnPage(t *testing.T) {
	// The cookie is attached by the browser whoever asked for the request, so
	// on its own it says nothing about who wanted it sent. The echoed value is
	// what separates our page from somebody else's.
	twoReach(t, func(t *testing.T, r *reach) {
		issued := signIn(t, r, "admin")
		other := signIn(t, r, "reader")

		for _, c := range []struct {
			what string
			csrf string
			want int
		}{
			{"nothing echoed", "", http.StatusUnauthorized},
			{"a guess", "not-the-value", http.StatusUnauthorized},
			{"another session's value", other.CSRF, http.StatusUnauthorized},
			{"its own value", issued.CSRF, http.StatusCreated},
		} {
			got := asBrowser(t, r, issued, http.MethodPost, "/v1/products", c.csrf).Code
			if got != c.want {
				t.Errorf("declaring a product with %s answered %d, want %d", c.what, got, c.want)
			}
		}
	})
}

func TestReadingFromABrowserNeedsNothingEchoed(t *testing.T) {
	// The guard is against a request being made, not against one being read.
	// Requiring it on reads would break every ordinary page load for nothing.
	twoReach(t, func(t *testing.T, r *reach) {
		// GET alone, because it is the only safe method this API routes.
		// HEAD and OPTIONS are treated as safe by the guard regardless, so
		// that adding a route for either later does not quietly make it one
		// that has to echo a value to be read.
		issued := signIn(t, r, "reader")
		if got := asBrowser(t, r, issued, http.MethodGet, "/v1/products", "").Code; got != http.StatusOK {
			t.Errorf("GET with nothing echoed answered %d, want 200", got)
		}
	})
}

func TestAKeyIsNotAskedToEchoAnythingOrToSayWhereItCameFrom(t *testing.T) {
	// Nothing sends a key automatically, so there is no request somebody else
	// can cause a pipeline to make, and the guard would protect nothing while
	// breaking every build.
	//
	// A write is what tests this. A read is safe for every credential type, so
	// asserting on one would pass just as well if keys *were* being asked to
	// echo a value — which is what the first version of this test did.
	twoReach(t, func(t *testing.T, r *reach) {
		if got := r.asKey(t, http.MethodGet,
			"/v1/products/mine/streams/master/variants/broadcom/scans"); got != http.StatusOK {
			t.Errorf("a key reading its receipts answered %d, want 200", got)
		}

		// No Origin, no echoed value, and a method that changes something.
		// A build sends exactly this.
		req := upload(t, "/v1/products/mine/streams/master/variants/broadcom/scans",
			inventory(nowish(), "libc6"))
		req.Header.Set("Authorization", "Bearer "+r.key)
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Errorf("a build upload carrying no forgery guard answered %d, want 202: %s",
				rec.Code, rec.Body.String())
		}
	})
}

func TestAWriteFromSomebodyElsesPageIsRefused(t *testing.T) {
	// The forgery guard, on the path that has no session to hang a value on.
	// A proxy authenticates from its own cookie, which the browser attaches
	// without anybody asking — so the credential arrives whoever caused the
	// request, and where it came from is what separates the two.
	twoReach(t, func(t *testing.T, r *reach) {
		for _, c := range []struct {
			what   string
			origin string
			want   int
		}{
			{"somebody else's page", "https://evil.example", http.StatusUnauthorized},
			{"no origin at all", "", http.StatusUnauthorized},
			{"a lookalike host", "http://example.com.evil.example", http.StatusUnauthorized},
			{"our own page", "http://example.com", http.StatusCreated},
		} {
			req := httptest.NewRequest(http.MethodPost, "/v1/products",
				strings.NewReader(`{"name":"`+strings.ReplaceAll(c.what, " ", "-")+`"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(testHeader, "admin")
			if c.origin != "" {
				req.Header.Set("Origin", c.origin)
			}
			rec := httptest.NewRecorder()
			r.handler.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Errorf("a write from %s answered %d, want %d", c.what, rec.Code, c.want)
			}
		}
	})
}

func TestReadingIsNotGuardedByWhereItCameFrom(t *testing.T) {
	// The guard is against a request being made, not against one being read.
	// Applying it to reads would break every ordinary page load for nothing.
	twoReach(t, func(t *testing.T, r *reach) {
		req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		req.Header.Set(testHeader, "reader")
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("a read with no origin answered %d, want 200", rec.Code)
		}
	})
}

func TestSigningOutStopsTheCookieWorking(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		issued := signIn(t, r, "reader")

		out := asBrowser(t, r, issued, http.MethodDelete, "/v1/session", issued.CSRF)
		if out.Code != http.StatusNoContent {
			t.Fatalf("signing out answered %d: %s", out.Code, out.Body.String())
		}
		// The browser is told to drop it as well as the row being deleted.
		if cleared := out.Header().Get("Set-Cookie"); !strings.Contains(cleared, access.CookieName(access.SessionCookie, false)+"=") ||
			!strings.Contains(cleared, "Max-Age=0") {
			t.Errorf("signing out did not clear the cookie: %q", cleared)
		}

		if got := asBrowser(t, r, issued, http.MethodGet, "/v1/products", "").Code; got != http.StatusUnauthorized {
			t.Errorf("the session still worked after signing out: %d", got)
		}
	})
}

func TestSigningOutIsNotSomethingAKeyCanDo(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		if got := r.asKey(t, http.MethodDelete, "/v1/session"); got == http.StatusNoContent {
			t.Error("a pipeline signed out of a session it never had")
		}
	})
}

func TestASessionForSomebodyGrantedNothingReachesNothing(t *testing.T) {
	// Issuing a session does not decide anything about access. Somebody whose
	// roles were withdrawn between sign-in and now is refused on the next
	// request rather than at the next sign-in.
	twoReach(t, func(t *testing.T, r *reach) {
		issued := signIn(t, r, "nothing")
		if got := asBrowser(t, r, issued, http.MethodGet, "/v1/products", "").Code; got != http.StatusUnauthorized {
			t.Errorf("a session for somebody granted nothing answered %d, want 401", got)
		}
	})
}

func TestAnAdministratorCanCutSomebodyOffAtOnce(t *testing.T) {
	// Roles and group mappings are re-read at sign-in, so withdrawing one
	// takes effect then. Somebody leaving cannot wait for that.
	twoReach(t, func(t *testing.T, r *reach) {
		issued := signIn(t, r, "reader")
		if got := asBrowser(t, r, issued, http.MethodGet, "/v1/products", "").Code; got != http.StatusOK {
			t.Fatalf("the session did not work to begin with: %d", got)
		}

		if got := r.as(t, "admin", http.MethodDelete, "/v1/people/reader/sessions"); got != http.StatusNoContent {
			t.Fatalf("ending their sessions answered %d", got)
		}
		if got := asBrowser(t, r, issued, http.MethodGet, "/v1/products", "").Code; got != http.StatusUnauthorized {
			t.Errorf("the session survived being ended: %d", got)
		}
	})
}

func TestCuttingSomebodyOffIsNotSomethingTheyCanDoToEachOther(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		for _, who := range []string{"reader", "triager", "approver", "private-triage"} {
			if got := r.as(t, who, http.MethodDelete, "/v1/people/admin/sessions"); got != http.StatusForbidden {
				t.Errorf("%s ended an administrator's sessions: %d", who, got)
			}
		}
	})
}

func TestAnAdministratorCanWithdrawATokenWhoseOwnerHasGone(t *testing.T) {
	// The ones that matter are found when somebody leaves and nobody knows
	// what breaks if they are turned off.
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		person, err := r.rights.ByIdentity(ctx, "reader")
		if err != nil {
			t.Fatal(err)
		}
		_, secret, err := r.rights.NewToken(ctx, person.ID, "scripting", nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.rights.ResolveToken(ctx, secret); err != nil {
			t.Fatalf("the token did not work to begin with: %v", err)
		}

		if got := r.as(t, "reader", http.MethodDelete, "/v1/people/reader/tokens/scripting"); got != http.StatusForbidden {
			t.Errorf("somebody withdrew a token through the administration path: %d", got)
		}
		if got := r.as(t, "admin", http.MethodDelete, "/v1/people/reader/tokens/scripting"); got != http.StatusNoContent {
			t.Fatalf("an administrator could not withdraw it: %d", got)
		}
		if _, err := r.rights.ResolveToken(ctx, secret); err == nil {
			t.Error("the token still worked after being withdrawn")
		}
	})
}

func TestATokenIsACredentialLikeAnyOther(t *testing.T) {
	// It authenticates through the same one resolution step every other
	// credential goes through, so nothing downstream knows which door it came
	// through.
	twoReach(t, func(t *testing.T, r *reach) {
		person, err := r.rights.ByIdentity(t.Context(), "reader")
		if err != nil {
			t.Fatal(err)
		}
		_, secret, err := r.rights.NewToken(t.Context(), person.ID, "scripting", nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}

		if got := r.withKey(t, secret, http.MethodGet, "/v1/products").code; got != http.StatusOK {
			t.Errorf("a personal token could not read what its owner reads: %d", got)
		}
		// And reaches no further than its owner does.
		if got := r.withKey(t, secret, http.MethodGet, "/v1/products/theirs/streams").code; got != http.StatusNotFound {
			t.Errorf("a personal token reached past its owner: %d", got)
		}
		// Nor into administration.
		if got := r.withKey(t, secret, http.MethodGet, "/v1/people").code; got != http.StatusForbidden {
			t.Errorf("a personal token reached administration: %d", got)
		}
	})
}

func TestATokenCannotMintItselfAWiderOne(t *testing.T) {
	// The escalation this guard exists for. Minting resolves through the
	// owner, so without it a token narrowed to one product asks for one
	// narrowed to nothing and is given it — and an administrator's narrowed
	// token mints one carrying administration. Every limit on a token would be
	// exactly one request deep, the lifetime ceiling included.
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		person, err := r.rights.ByIdentity(ctx, "admin")
		if err != nil {
			t.Fatal(err)
		}
		mine, err := r.rights.ByIdentity(ctx, "reader")
		if err != nil {
			t.Fatal(err)
		}
		_ = mine

		_, narrow, err := r.rights.NewToken(ctx, person.ID, "narrow", nil, time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}

		mint := func(secret, body string) int {
			req := httptest.NewRequest(http.MethodPost, "/v1/tokens", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+secret)
			rec := httptest.NewRecorder()
			r.handler.ServeHTTP(rec, req)
			return rec.Code
		}

		if got := mint(narrow, `{"name":"wider"}`); got != http.StatusForbidden {
			t.Errorf("a token minted another: %d", got)
		}
		if got := r.withKey(t, narrow, http.MethodDelete, "/v1/tokens/narrow").code; got != http.StatusForbidden {
			t.Errorf("a token withdrew another: %d", got)
		}
		// And the owner, signed in, still can.
		req := httptest.NewRequest(http.MethodPost, "/v1/tokens", strings.NewReader(`{"name":"by-hand"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(testHeader, "admin")
		fromOurOwnPage(req)
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Errorf("somebody signed in could not mint a token: %d %s", rec.Code, rec.Body.String())
		}
	})
}
