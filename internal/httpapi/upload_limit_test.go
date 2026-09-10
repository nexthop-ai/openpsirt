package httpapi_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// limitedIngest is the ingest fixture with a document limit small enough to
// exceed from a test.
func limitedIngest(t *testing.T, limits sbom.Limits, fn func(t *testing.T, f *ingestFixture)) {
	t.Helper()
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		rights := access.NewStore(db.DB)
		_, secret, err := rights.NewKey(ctx, "nightly", access.Scope{ProductID: product.ID})
		if err != nil {
			t.Fatal(err)
		}

		q := queue.New(db, queue.DefaultOptions())
		handler, _ := httpapi.New(quiet, nil, httpapi.Ingest{
			DB: db, Queue: q, Limits: limits,
			Access: access.NewResolver(rights, access.Trust{}),
		})
		fn(t, &ingestFixture{
			handler: handler, db: db, queue: q, key: secret,
			path: "/v1/products/sonic/streams/master/variants/broadcom/scans",
		})
	})
}

func TestAFormLargerThanTheUploadLimitIsRefusedBeforeItIsRead(t *testing.T) {
	// The operation's body limit only applies to a body read whole. A form is
	// read part by part, and without a cap on the request a part of any size
	// is spooled to disk in full before the document limit sees it.
	limitedIngest(t, sbom.Limits{MaxBytes: 4096}, func(t *testing.T, f *ingestFixture) {
		// Well-formed, so that reaching the parser would be refused for its
		// size by the document limit — as a 422 — rather than as a request
		// that was never read. The padding is whitespace the parser accepts.
		padded := strings.Replace(inventory(nowish(), "libc6"), "\n", strings.Repeat(" ", 4096)+"\n", 8)
		if len(padded) <= 2*4096 {
			t.Fatalf("the padded inventory is %d bytes, which does not exceed the request limit", len(padded))
		}

		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, f.sending(upload(t, f.path, padded)))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("an oversized form returned %d, want 413: %s", rec.Code, rec.Body.String())
		}

		depth, err := f.queue.Depth(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if depth != 0 {
			t.Errorf("%d jobs were left behind by a refused upload", depth)
		}

		// And the cap does not stand in the way of an upload within it.
		code, result := f.send(t, upload(t, f.path, inventory(nowish(), "libc6")))
		if code != http.StatusAccepted || result.Outcome != "queued" {
			t.Errorf("an upload within the limit returned %d %q", code, result.Outcome)
		}
	})
}
