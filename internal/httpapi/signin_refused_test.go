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
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
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
