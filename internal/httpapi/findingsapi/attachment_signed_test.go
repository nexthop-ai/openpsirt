// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// signing is a store with a signing authority of its own: it hands out an
// address carrying the disposition and type it was asked for, as an object
// store does.
type signing struct{ attach.Storage }

func (signing) URLFor(_ context.Context, key string, _ time.Duration,
	disposition, contentType string) (string, error) {

	return "https://store.example/" + key + "?" + url.Values{
		"response-content-disposition": {disposition},
		"response-content-type":        {contentType},
	}.Encode(), nil
}

func TestAFileFromAStoreThatSignsIsHandedOverAsASignedAddress(t *testing.T) {
	// Everything but an inline image leaves an object-store deployment by a
	// 303 to a short-lived address. The address carries the disposition this
	// deployment chose, and nothing in between may cache the answer.
	httpapitest.ReachAdjusted(t, httpapitest.CastSeed.Two, func(deps *core.Deps) {
		deps.Files = signing{deps.Files}
	}, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		token := r.Attached(t, "triager")

		req := httptest.NewRequest(http.MethodGet, "/v1/attachments/"+token, nil)
		req.Header.Set(httpapitest.TestHeader, "triager")
		httpapitest.FromOurOwnPage(req)
		rec := httptest.NewRecorder()
		r.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusSeeOther {
			t.Fatalf("fetching a stored text file answered %d, want 303: %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
			t.Errorf("the redirect may be cached: Cache-Control %q", got)
		}
		address, err := url.Parse(rec.Header().Get("Location"))
		if err != nil || address.Host != "store.example" {
			t.Fatalf("the redirect points at %q", rec.Header().Get("Location"))
		}
		if got := address.Query().Get("response-content-disposition"); !strings.HasPrefix(got, "attachment;") ||
			!strings.Contains(got, `filename="evidence.txt"`) {
			t.Errorf("the address asks the store to serve it as %q", got)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("the redirect carried the file's bytes as well: %q", rec.Body.String())
		}
	})
}
