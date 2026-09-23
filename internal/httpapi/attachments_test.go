// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAskingAboutAnIssueSomewhereElseSaysNothingAboutIt(t *testing.T) {
	// The resolver looked an identifier up across the whole deployment and
	// then asked how disclosed it is *here* — and "no undisclosed findings in
	// this product" and "not in this product at all" were the same answer, so
	// an issue filed against another product read as public here. Any reader
	// of any product could then confirm, one request at a time, whether a name
	// exists somewhere in the deployment: 200 for one that does and 404 for
	// one that does not.
	//
	// That is what makes a minted identifier guessable again. The random draw
	// stops the sequence being walked; a confirm-or-deny oracle turns it back
	// into a space somebody can check a guess against.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		hidden := r.embargoed(t)

		// An issue recorded in the deployment and not in this product, which
		// is what the resolver could not tell from an issue nobody has ever
		// filed. Written directly: what is being measured is the resolver's
		// answer, and the shortest way to a vulnerability row that this
		// product holds nothing against is to make one.
		if _, err := r.db.DB.NewInsert().Model(&finding.Vulnerability{
			Identifier: "CVE-2026-ELSEWHERE", IdentifierFolded: "cve-2026-elsewhere",
			Severity: "high",
		}).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		at := func(product, issue string) int {
			return asPerson(t, r, "triager", http.MethodGet,
				"/v1/products/"+product+"/issues/"+issue+"/attachments", "").Code
		}

		// The product the issue is actually in refuses this reader, correctly:
		// it is undisclosed and they hold no private role.
		if got := at("mine", hidden); got != http.StatusNotFound {
			t.Errorf("an undisclosed issue answered %d in its own product", got)
		}
		// A name nobody has ever used answers the same.
		absent := at("mine", "OPENPSIRT-2026-000001")
		if absent != http.StatusNotFound {
			t.Errorf("a name nobody has used answered %d", absent)
		}
		// And so must a real name asked about somewhere it is not, or the two
		// answers tell a guesser which guesses were right.
		if got := at("mine", "CVE-2026-ELSEWHERE"); got != absent {
			t.Errorf("an issue that is not in this product answered %d where a name "+
				"nobody has used answered %d", got, absent)
		}
	})
}

// The attachment operations carry REQ-70's control, and nothing exercised the
// layer that carries it.
//
// The store below is well covered — readability against the issue, the
// embargo, the administrator-only redaction — but the two operations that
// reach it had no test at all: not their path, not their operation id, and no
// row in the authorization matrix. A handler passing the wrong subject, or
// dropping the error from the fetch, would break the one control AGENTS.md
// singles out with a green suite.
func TestWhoMayFetchAndRedactAnAttachment(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		token := r.attached(t, "triager")

		at := "/v1/attachments/" + token
		for _, c := range []struct {
			who  string
			want int
		}{
			// Whoever may read the issue may read what its text refers to.
			{"triager", http.StatusOK},
			{"reader", http.StatusOK},
			// An administrator holding no read role here does not.
			// Administering the catalog is not reading its findings, and an
			// attachment is authorized against the finding it hangs off.
			{"admin", http.StatusForbidden},
			// Somebody recognized who was granted nothing is refused before
			// any of that.
			{"nothing", http.StatusUnauthorized},
		} {
			if got := r.body(t, c.who, http.MethodGet, at); got.code != c.want {
				t.Errorf("fetching as %q answered %d, want %d: %s",
					c.who, got.code, c.want, got.text)
			}
		}
		// A pipeline key may send scans and read no attachment.
		if got := r.withKey(t, r.key, http.MethodGet, at); got.code != http.StatusForbidden {
			t.Errorf("a pipeline key fetched an attachment: %d %s", got.code, got.text)
		}

		// Removing it is administration, and the declaration says so.
		if got := asPerson(t, r, "triager", http.MethodDelete, at,
			`{"reason":"Not mine to remove."}`); got.Code != http.StatusForbidden {
			t.Errorf("a triager removed a file: %d %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "admin", http.MethodDelete, at,
			`{"reason":"It carried a credential."}`); got.Code != http.StatusNoContent {
			t.Fatalf("an administrator could not remove a file: %d %s",
				got.Code, got.Body.String())
		}

		// The record and the reference remain, and the bytes are gone on
		// purpose — which is 410 rather than 404.
		if got := r.body(t, "triager", http.MethodGet, at); got.code != http.StatusGone {
			t.Errorf("a redacted file answered %d, want 410: %s", got.code, got.text)
		}
	})
}

// attached puts one file against the scanned issue and returns its token.
func (r *reach) attached(t *testing.T, who string) string {
	t.Helper()
	body := &bytes.Buffer{}
	form := multipart.NewWriter(body)
	part, err := form.CreateFormFile("file", "evidence.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("the request that answered before anybody signed in")); err != nil {
		t.Fatal(err)
	}
	// Hanging off the issue rather than off text somebody is part way
	// through writing, so it is listed at once and never swept.
	if err := form.WriteField("evidence", "true"); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost,
		"/v1/products/mine/issues/CVE-2026-9999/attachments", body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set(testHeader, who)
	fromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("attaching a file answered %d: %s", rec.Code, rec.Body.String())
	}
	var stored struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Token == "" {
		t.Fatalf("attaching a file returned no token: %s", rec.Body.String())
	}
	return stored.Token
}
