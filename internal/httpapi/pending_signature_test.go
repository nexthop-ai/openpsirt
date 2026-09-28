// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A sign-in in progress is carried by the browser, signed with this
// deployment's key. One whose signature was made over a different payload is
// refused, and no session is issued: a signature lifted from one sign-in does
// not vouch for a payload somebody edited.
//
// Verified by deleting the `!hmac.Equal` refusal in openPending: the spliced
// cookie then completes the sign-in with a 302.
func TestASignatureFromAnotherPayloadDoesNotOpenASignIn(t *testing.T) {
	twoSignIn(t, func(t *testing.T, r *signInReach) {
		payload := func(back string) []byte {
			body, err := json.Marshal(map[string]any{
				"pending": map[string]string{
					"State": "the-state", "Nonce": "the-nonce", "Verifier": "the-verifier",
				},
				"return": back,
				"minted": time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
		complete := func(cookie string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet,
				"/v1/sign-in/stub/callback?state=the-state&code=a-code", nil)
			req.Header.Set("Cookie", "openpsirt_pending="+cookie)
			rec := httptest.NewRecorder()
			r.handler.ServeHTTP(rec, req)
			return rec
		}

		// The sealed value as issued completes, so the refusal below is the
		// signature rather than the path.
		issued := r.sealed(t, payload("/findings"))
		if got := complete(issued); got.Code != http.StatusFound {
			t.Fatalf("a sign-in sealed here answered %d: %s", got.Code, got.Body.String())
		}

		_, signature, _ := strings.Cut(issued, ".")
		spliced := base64.RawURLEncoding.EncodeToString(payload("/queue")) + "." + signature
		got := complete(spliced)
		if got.Code == http.StatusFound {
			t.Fatalf("a payload carrying another payload's signature completed a sign-in to %q",
				got.Header().Get("Location"))
		}
		if hasSession(got.Result().Cookies()) {
			t.Error("a spliced sign-in was issued a session")
		}
	})
}
