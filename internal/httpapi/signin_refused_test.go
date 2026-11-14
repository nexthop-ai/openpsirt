// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// The callback is a page a provider sends a browser to, so a refusal there
// lands on the interface's one no-access screen, the same address and body for
// every reason. Told apart, the reasons say whether a name is real.
func TestEveryRefusedSignInLandsOnTheOneNoAccessScreen(t *testing.T) {
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		left, err := r.rights.Ensure(t.Context(), "left", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.rights.Claim(t.Context(), left.ID, "left"); err != nil {
			t.Fatal(err)
		}
		if err := r.rights.GrantRole(t.Context(), left.ID, r.product, access.PublicRead); err != nil {
			t.Fatal(err)
		}
		if _, err := r.rights.Deactivate(t.Context(), left.ID); err != nil {
			t.Fatal(err)
		}

		// Everything a browser is told, apart from the moment it was told.
		told := func(rec *httptest.ResponseRecorder) string {
			header := rec.Header().Clone()
			header.Del("Date")
			return fmt.Sprint(rec.Code, header, rec.Body.String())
		}
		var first string
		for i, c := range []struct {
			what  string
			says  *signin.Identity
			fail  error
			state string
		}{
			{what: "somebody granted nothing", says: &signin.Identity{Subject: "s-ungranted", Username: "ungranted"}},
			{what: "a stranger", says: &signin.Identity{Subject: "s-stranger", Username: "a-stranger"}},
			{what: "somebody who has left", says: &signin.Identity{Subject: "s-left", Username: "left"}},
			{what: "a provider that failed", says: &signin.Identity{Subject: "1", Username: "granted"}, fail: errClientSecretRejected},
			{what: "a state that was never sent", says: &signin.Identity{Subject: "1", Username: "granted"}, state: "somebody-elses"},
		} {
			r.provider.Says, r.provider.Fail = c.says, c.fail
			state := c.state
			if state == "" {
				state = "the-state"
			}
			rec := callback(t, r, state, "a-code", true)
			if !noAccess(rec) {
				t.Errorf("%s answered %d to %q, want 303 to /?no-access: %s",
					c.what, rec.Code, rec.Header().Get("Location"), rec.Body.String())
			}
			if hasSession(rec.Result().Cookies()) {
				t.Errorf("%s was handed a session", c.what)
			}
			if i == 0 {
				first = told(rec)
			} else if told(rec) != first {
				t.Errorf("%s answered %q, unlike the first refusal's %q", c.what, told(rec), first)
			}
		}
	})
}

// A role across every product admits its holder before any product is
// declared, at sign-in and on every request after, and reaches nothing there.
func TestARoleAcrossEveryProductSignsSomebodyInBeforeAnyProductExists(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		person, err := rights.Ensure(ctx, "the-security-team", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.Claim(ctx, person.ID, "the-security-team"); err != nil {
			t.Fatal(err)
		}
		for _, role := range []access.Role{
			access.PublicRead, access.PrivateRead, access.SecurityTestingRead,
			access.PublicTriage, access.SecurityTestingTriage,
		} {
			if err := rights.GrantEstateRole(ctx, person.ID, role); err != nil {
				t.Fatal(err)
			}
		}
		provider := &httpapitest.StubProvider{
			Says: &signin.Identity{Subject: "1", Username: "the-security-team"},
		}
		handler, _ := httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, core.Deps{
			Mode: func(context.Context) access.Mode { return access.Direct },
			DB:   db, Queue: queue.New(db, queue.DefaultOptions()),
			Access:    access.NewResolver(rights, access.Trust{}).OverPlainHTTP(true),
			Providers: map[string]signin.Provider{"stub": provider},
			PlainHTTP: true,
			BaseURL:   "http://example.com",
		})

		rec := callback(t, &signInReach{handler: handler}, "the-state", "a-code", true)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
			t.Fatalf("signing in answered %d to %q, want 302 to /: %s",
				rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		cookies := rec.Result().Cookies()
		if !hasSession(cookies) {
			t.Fatal("signing in handed out no session")
		}
		get := func(path string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
			out := httptest.NewRecorder()
			handler.ServeHTTP(out, req)
			return out
		}

		me := get("/v1/session/me")
		if me.Code != http.StatusOK {
			t.Fatalf("the current user answered %d, want 200: %s", me.Code, me.Body.String())
		}
		// Said, so a screen tells an empty catalog from nothing granted.
		var who struct {
			Everywhere bool              `json:"everywhere"`
			Reach      []json.RawMessage `json:"reach"`
		}
		if err := json.Unmarshal(me.Body.Bytes(), &who); err != nil {
			t.Fatal(err)
		}
		if !who.Everywhere || len(who.Reach) != 0 {
			t.Errorf("the current user says everywhere %v and reaches %d products", who.Everywhere, len(who.Reach))
		}
		// Admitted, and reaching nothing product-scoped.
		for _, path := range []string{"/v1/products", "/v1/findings"} {
			got := get(path)
			if got.Code != http.StatusOK {
				t.Errorf("%s answered %d, want 200: %s", path, got.Code, got.Body.String())
				continue
			}
			var out struct {
				Items []json.RawMessage `json:"items"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
				t.Fatal(fmt.Errorf("%s: %w", path, err))
			}
			if len(out.Items) != 0 {
				t.Errorf("%s lists %d items before any product exists", path, len(out.Items))
			}
		}
	})
}

// A browser the trusted proxy names and this deployment refuses has no callback
// to be redirected from. The list of ways in says the proxy named the browser,
// the same for a person let in, a person refused and a stranger, so the
// interface draws the no-access screen without learning why.
func TestTheWaysInSayWhetherTheProxyNamedTheBrowser(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ways := func(who string) string {
			t.Helper()
			got := r.Body(t, who, http.MethodGet, "/v1/sign-in")
			if got.Code != http.StatusOK {
				t.Fatalf("the ways in answered %d to %q: %s", got.Code, who, got.Text)
			}
			return got.Text
		}
		named := ways("reader")
		if !strings.Contains(named, `"named_by_proxy":true`) {
			t.Errorf("a browser the proxy named is not said to be: %s", named)
		}
		for _, who := range []string{"nobody-granted-anything", "a-stranger"} {
			if got := ways(who); got != named {
				t.Errorf("%q is told %s, unlike somebody let in: %s", who, got, named)
			}
			if got := r.Body(t, who, http.MethodGet, "/v1/session/me"); got.Code != http.StatusUnauthorized {
				t.Errorf("%q read themselves: %d", who, got.Code)
			}
		}
		if got := ways(""); strings.Contains(got, "named_by_proxy") {
			t.Errorf("a browser the proxy did not name is said to be: %s", got)
		}
		// The answer turns on who asks, so no cache may share it.
		req := httptest.NewRequest(http.MethodGet, "/v1/sign-in", nil)
		req.Header.Set(httpapitest.TestHeader, "reader")
		rec := httptest.NewRecorder()
		r.Handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("the ways in may be cached: Cache-Control %q", got)
		}
	})
}

// keyFault fails the read of the sign-in key once armed, and nothing else.
type keyFault struct{ armed, fired bool }

func (f *keyFault) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	if !f.armed || f.fired || !strings.Contains(e.Query, setting.SignInKey) {
		return ctx
	}
	f.fired = true
	failed, cancel := context.WithCancel(ctx)
	cancel()
	return failed
}

func (f *keyFault) AfterQuery(context.Context, *bun.QueryEvent) {}

// A sign-in whose key could not be read on the way back is this deployment's
// fault, so it lands on the try-again screen and never on the no-access one:
// telling somebody granted access to ask for it sends them to the wrong person.
func TestASignInWhoseKeyCouldNotBeReadIsAFaultNeverARefusal(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		fault := &keyFault{}
		handle := dbtest.Hooked(db, fault)
		provider := &httpapitest.StubProvider{Says: &signin.Identity{Subject: "1", Username: "granted"}}
		handler, _ := httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, core.Deps{
			Mode: func(context.Context) access.Mode { return access.Direct },
			DB:   handle, Queue: queue.New(handle, queue.DefaultOptions()),
			Access:    access.NewResolver(access.NewStore(handle.DB), access.Trust{}).OverPlainHTTP(true),
			Providers: map[string]signin.Provider{"stub": provider},
			PlainHTTP: true,
			BaseURL:   "http://example.com",
		})
		begun := httptest.NewRecorder()
		handler.ServeHTTP(begun, httptest.NewRequest(http.MethodGet, "/v1/sign-in/stub", nil))
		if begun.Code != http.StatusFound {
			t.Fatalf("starting a sign-in answered %d", begun.Code)
		}
		fault.armed = true
		req := httptest.NewRequest(http.MethodGet, "/v1/sign-in/stub/callback?state=the-state&code=a-code", nil)
		for _, cookie := range begun.Result().Cookies() {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if !fault.fired {
			t.Fatal("the key was never read on the way back, so this checked nothing")
		}
		if !faulted(rec) {
			t.Errorf("a sign-in whose key could not be read answered %d to %q, want the try-again screen",
				rec.Code, rec.Header().Get("Location"))
		}
		if hasSession(rec.Result().Cookies()) {
			t.Error("a sign-in whose key could not be read was handed a session")
		}
	})
}

// A provider that does not answer, from an outage, a network failure or a
// server error, lands a returning sign-in on the try-again screen. A provider
// turning somebody down still lands it on the no-access screen.
func TestAProviderThatDoesNotAnswerIsAFaultNeverARefusal(t *testing.T) {
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		r.provider.Says = &signin.Identity{Subject: "1", Username: "granted"}
		r.provider.Fail = fmt.Errorf("%w: the token endpoint answered 503", signin.ErrUnanswered)
		rec := callback(t, r, "the-state", "a-code", true)
		if !faulted(rec) {
			t.Fatalf("a provider that did not answer answered %d to %q, want the try-again screen",
				rec.Code, rec.Header().Get("Location"))
		}
		if strings.Contains(rec.Body.String(), "503") {
			t.Errorf("the answer repeats why: %s", rec.Body)
		}
		if hasSession(rec.Result().Cookies()) {
			t.Error("a provider that did not answer handed out a session")
		}

		r.provider.Fail = errClientSecretRejected
		if rec := callback(t, r, "the-state", "a-code", true); !noAccess(rec) {
			t.Errorf("a provider turning the sign-in down answered %d to %q, want the no-access screen",
				rec.Code, rec.Header().Get("Location"))
		}

		// What a provider sends the browser back with, in place of a code.
		for said, unanswered := range map[string]bool{
			"temporarily_unavailable": true, "server_error": true, "access_denied": false,
		} {
			rec := callback(t, r, "the-state", "&error="+said, true)
			if unanswered && !faulted(rec) {
				t.Errorf("a provider saying %s answered %d to %q, want the try-again screen",
					said, rec.Code, rec.Header().Get("Location"))
			}
			if !unanswered && !noAccess(rec) {
				t.Errorf("a provider saying %s answered %d to %q, want the no-access screen",
					said, rec.Code, rec.Header().Get("Location"))
			}
		}
	})
}
