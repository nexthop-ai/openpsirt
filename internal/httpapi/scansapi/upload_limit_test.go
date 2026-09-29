// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// limitedIngest is the ingest fixture with a document limit small enough to
// exceed from a test.
func limitedIngest(t *testing.T, limits sbom.Limits, fn func(t *testing.T, f *httpapitest.IngestFixture)) {
	t.Helper()
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		product := fixture.New(t, db).Product
		rights := access.NewStore(db.DB)
		_, secret, err := rights.NewKey(ctx, "nightly", access.Scope{ProductID: product.ID})
		if err != nil {
			t.Fatal(err)
		}

		q := queue.New(db, queue.DefaultOptions())
		handler, _ := httpapi.New(quiet, nil, core.Deps{
			DB: db, Queue: q, Limits: limits,
			Access: access.NewResolver(rights, access.Trust{}),
		})
		fn(t, &httpapitest.IngestFixture{
			Handler: handler, DB: db, Queue: q, Key: secret,
			Path: "/v1/products/" + fixture.ProductName + "/streams/" + fixture.BranchName +
				"/variants/" + fixture.CustomerVariant + "/scans",
		})
	})
}

func TestAFormLargerThanTheUploadLimitIsRefusedBeforeItIsRead(t *testing.T) {
	// The operation's body limit only applies to a body read whole. A form is
	// read part by part, and without a cap on the request a part of any size
	// is spooled to disk in full before the document limit sees it.
	limitedIngest(t, sbom.Limits{MaxBytes: 4096}, func(t *testing.T, f *httpapitest.IngestFixture) {
		// Well-formed, so that reaching the parser would be refused for its
		// size by the document limit — as a 422 — rather than as a request
		// that was never read. The padding is whitespace the parser accepts.
		padded := strings.Replace(httpapitest.Inventory(httpapitest.Nowish(), "libc6"), "\n", strings.Repeat(" ", 4096)+"\n", 8)
		if len(padded) <= 2*4096 {
			t.Fatalf("the padded inventory is %d bytes, which does not exceed the request limit", len(padded))
		}

		rec := httptest.NewRecorder()
		f.Handler.ServeHTTP(rec, f.Sending(httpapitest.Upload(t, f.Path, padded)))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("an oversized form returned %d, want 413: %s", rec.Code, rec.Body.String())
		}

		depth, err := f.Queue.Depth(t.Context(), queue.Parse)
		if err != nil {
			t.Fatal(err)
		}
		if depth != 0 {
			t.Errorf("%d jobs were left behind by a refused upload", depth)
		}

		// And the cap does not stand in the way of an upload within it.
		code, result := f.Send(t, httpapitest.Upload(t, f.Path, httpapitest.Inventory(httpapitest.Nowish(), "libc6")))
		if code != http.StatusAccepted || result.Outcome != "queued" {
			t.Errorf("an upload within the limit returned %d %q", code, result.Outcome)
		}
	})
}
