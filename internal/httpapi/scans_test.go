package httpapi_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// inventory is an inventory as a build would send one, built around a time so
// a test can place one scan before another.
func inventory(builtAt time.Time, component string) string {
	return fmt.Sprintf(`{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "serialNumber": "urn:uuid:%x",
	  "metadata": {
	    "timestamp": %q,
	    "component": {"bom-ref": "root", "name": "sonic-broadcom.bin", "version": "1.0"}
	  },
	  "components": [{"bom-ref": "a", "name": %q, "version": "2.41", "purl": "pkg:deb/debian/%s@2.41"}],
	  "dependencies": [{"ref": "root", "dependsOn": ["a"]}]
	}`, builtAt.UnixNano(), builtAt.UTC().Format(time.RFC3339), component, component)
}

// spdxInventory is the same inventory in the other format, so the upload path
// can be shown to take either rather than only the one it was written against.
func spdxInventory(builtAt time.Time, component string) string {
	return fmt.Sprintf(`{
	  "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
	  "name": "sonic-broadcom.bin",
	  "documentNamespace": "https://example.invalid/sonic/%x",
	  "creationInfo": {"created": %q, "creators": ["Tool: something-1.0"]},
	  "packages": [
	    {"SPDXID": "SPDXRef-root", "name": "sonic-broadcom.bin", "versionInfo": "1.0", "downloadLocation": "NOASSERTION"},
	    {"SPDXID": "SPDXRef-a", "name": %q, "versionInfo": "2.41", "downloadLocation": "NOASSERTION",
	     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
	                       "referenceLocator": "pkg:deb/debian/%s@2.41"}]}
	  ],
	  "relationships": [
	    {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-root", "relationshipType": "DESCRIBES"},
	    {"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "DEPENDS_ON"}
	  ]
	}`, builtAt.UnixNano(), builtAt.UTC().Format(time.RFC3339), component, component)
}

const suppression = `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:x", "version": 1,
 "statements": [{"vulnerability": {"name": "CVE-2026-1"}, "status": "not_affected",
 "products": [{"@id": "pkg:deb/debian/libc6"}]}]}`

// nowish is a build time a moment ago, which every arrival check accepts.
func nowish() time.Time { return time.Now().UTC().Add(-time.Hour) }

// upload builds the multipart request a build sends.
func upload(t *testing.T, path, inventory string, suppressions ...string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)

	part, err := form.CreateFormFile("inventory", "sonic.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, inventory); err != nil {
		t.Fatal(err)
	}
	for i, s := range suppressions {
		part, err := form.CreateFormFile("suppressions", fmt.Sprintf("vex-%d.json", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	return req
}

// ingestFixture is a migrated database with one declared target and a server
// in front of it.
type ingestFixture struct {
	handler http.Handler
	db      *database.DB
	queue   *queue.Queue
	path    string
	// key is a pipeline's credential for the declared target, which is how a
	// build actually sends.
	key string
}

// sending presents the pipeline's credential, the way a build would.
func (f *ingestFixture) sending(req *http.Request) *http.Request {
	req.Header.Set("Authorization", "Bearer "+f.key)
	return req
}

func (f *ingestFixture) send(t *testing.T, req *http.Request) (int, httpapi.UploadResult) {
	t.Helper()
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, f.sending(req))
	var result httpapi.UploadResult
	if rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode response: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, result
}

// The four-engine form and the two-engine form of the same fixture. Which
// one a test uses is decided by the rule at dbtest.Two: a test that pins what
// a query does — what a list contains, what a filter hides, what a conflict
// looks like, what text comes back — runs on every engine, and a test that
// pins routing, who may reach what, or the shape of a response runs on two.
func eachIngest(t *testing.T, opts queue.Options, fn func(t *testing.T, f *ingestFixture)) {
	t.Helper()
	ingestOn(t, dbtest.Each, opts, fn)
}

func twoIngest(t *testing.T, opts queue.Options, fn func(t *testing.T, f *ingestFixture)) {
	t.Helper()
	ingestOn(t, dbtest.Two, opts, fn)
}

func ingestOn(t *testing.T, on engines, opts queue.Options, fn func(t *testing.T, f *ingestFixture)) {
	t.Helper()
	on(t, func(t *testing.T, db *database.DB) {
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

		// A key scoped to the product, which is the common case: a key cannot
		// imply which release an upload is for, so the upload states it.
		rights := access.NewStore(db.DB)
		_, secret, err := rights.NewKey(ctx, "nightly", access.Scope{ProductID: product.ID})
		if err != nil {
			t.Fatal(err)
		}

		q := queue.New(db, opts)
		handler, _ := httpapi.New(quiet, nil, httpapi.Ingest{
			DB: db, Queue: q,
			Access: access.NewResolver(rights, access.Trust{}),
			// Small enough that a test can write a document past it. Every
			// other bound is the default, which OrDefault fills in.
			Limits: sbom.Limits{MaxBytes: 4096},
		})
		fn(t, &ingestFixture{
			handler: handler, db: db, queue: q, key: secret,
			path: "/v1/products/sonic/streams/master/variants/broadcom/scans",
		})
	})
}

func TestAnUploadIsTakenAndLeavesWorkBehind(t *testing.T) {
	// Reading happens after the response, so what a successful upload has to
	// leave behind is the scan, its documents, and the work that will read
	// them — all of it, or none.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		built := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		code, result := f.send(t, upload(t, f.path, inventory(built, "libc6"), suppression, suppression))
		if code != http.StatusAccepted {
			t.Fatalf("POST returned %d, want 202", code)
		}
		if result.ScanID == 0 || result.Outcome != "queued" {
			t.Errorf("result is %+v", result)
		}
		if result.BuiltAt != built.Format(time.RFC3339) {
			t.Errorf("reported build time %q, want %q", result.BuiltAt, built.Format(time.RFC3339))
		}

		docs, err := ingest.NewDocuments(f.db.DB).List(t.Context(), result.ScanID)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 3 {
			t.Fatalf("held %d documents, want an inventory and two suppression sets", len(docs))
		}

		depth, err := f.queue.Depth(t.Context())
		if err != nil || depth != 1 {
			t.Errorf("%d jobs waiting, want 1 (%v)", depth, err)
		}
	})
}

func TestTheSameFileSentAgainReportsSuccess(t *testing.T) {
	// The ordinary case is a retry after a timeout that had in fact succeeded.
	// Failing it turns a landed scan into a red build, and the usual answer to
	// that is retry logic that swallows errors — which then hides real ones.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		built := time.Now().UTC().Add(-time.Hour)
		body := inventory(built, "libc6")

		code, first := f.send(t, upload(t, f.path, body))
		if code != http.StatusAccepted {
			t.Fatalf("first upload returned %d", code)
		}
		code, again := f.send(t, upload(t, f.path, body))
		if code != http.StatusOK {
			t.Fatalf("the same file again returned %d, want 200", code)
		}
		if again.Outcome != "already_held" || again.ScanID != first.ScanID {
			t.Errorf("second upload reported %+v, want the first scan %d", again, first.ScanID)
		}

		// It must not become a second piece of work, or the same scan is read
		// twice for no reason.
		if depth, _ := f.queue.Depth(t.Context()); depth != 1 {
			t.Errorf("%d jobs waiting after a repeat, want 1", depth)
		}
		docs, _ := ingest.NewDocuments(f.db.DB).List(t.Context(), first.ScanID)
		if len(docs) != 1 {
			t.Errorf("held %d documents after a repeat, want 1", len(docs))
		}
	})
}

func TestAnOlderScanIsRefusedAsAConflict(t *testing.T) {
	// Taking it would replace today's picture with yesterday's, reopening
	// closed findings with no symptom anyone would notice.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		now := time.Now().UTC()
		if code, _ := f.send(t, upload(t, f.path, inventory(now.Add(-time.Hour), "libc6"))); code != http.StatusAccepted {
			t.Fatalf("first upload returned %d", code)
		}
		code, _ := f.send(t, upload(t, f.path, inventory(now.Add(-2*time.Hour), "zlib1g")))
		if code != http.StatusConflict {
			t.Errorf("an older scan returned %d, want 409", code)
		}
	})
}

func TestAScanFromTheFutureIsRefusedAsABadRequest(t *testing.T) {
	// The producer's clock is wrong, which is a fault in what was sent rather
	// than a conflict with anything held. Accepting it would mean nothing
	// legitimate is ever newer, and that variant takes no further scans at all.
	twoIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		code, _ := f.send(t, upload(t, f.path, inventory(time.Now().UTC().Add(48*time.Hour), "libc6")))
		if code != http.StatusBadRequest {
			t.Errorf("a scan from the future returned %d, want 400", code)
		}
	})
}

func TestAnUndeclaredTargetSaysWhichPartIsMissing(t *testing.T) {
	twoIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		req := f.sending(upload(t, "/v1/products/sonic/streams/master/variants/mellanox/scans",
			inventory(time.Now().UTC().Add(-time.Hour), "libc6")))
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("an undeclared variant returned %d, want 404", rec.Code)
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte("mellanox")) {
			t.Errorf("the refusal does not name what is missing: %s", rec.Body.String())
		}
	})
}

func TestNothingIsStoredWhenTheBacklogIsFull(t *testing.T) {
	// Guarding what is actually at risk: other products' scans stuck behind a
	// queue that cannot drain. The caller is told to come back rather than
	// having tens of megabytes stored and then discarded.
	opts := queue.DefaultOptions()
	opts.MaxBacklog = 1
	eachIngest(t, opts, func(t *testing.T, f *ingestFixture) {
		now := time.Now().UTC()
		if code, _ := f.send(t, upload(t, f.path, inventory(now.Add(-2*time.Hour), "libc6"))); code != http.StatusAccepted {
			t.Fatalf("first upload returned %d", code)
		}
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, f.sending(upload(t, f.path, inventory(now.Add(-time.Hour), "zlib1g"))))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("an upload against a full backlog returned %d, want 503", rec.Code)
		}

		// It has to be refused on arrival rather than after the documents have
		// been stored and rolled back. Both leave the same rows behind — none
		// — so what distinguishes them is which refusal answered, and the cost
		// of the difference is a whole upload written and thrown away.
		if !bytes.Contains(rec.Body.Bytes(), []byte("already waiting to be read")) {
			t.Errorf("the upload was refused after being stored, not on arrival: %s", rec.Body.String())
		}

		count, err := f.db.DB.NewSelect().Model((*ingest.Scan)(nil)).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("%d scans recorded, want only the one that was taken", count)
		}
	})
}

func TestSomethingThatIsNotAnInventoryIsRefused(t *testing.T) {
	// A document naming no format at all. Both formats are read, so what is
	// left to refuse is a file that says it is neither — a fragment, or
	// something else entirely whose keys happen to look familiar.
	twoIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, f.sending(upload(t, f.path, `{"components": [{"name": "libc6"}]}`)))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("a document we cannot read returned %d, want 422", rec.Code)
		}
	})
}

func TestAnUploadInEitherFormatIsTaken(t *testing.T) {
	// One upload, one authorization, one arrival decision, whichever format
	// the build emits. The reader is chosen by the document rather than by the
	// request, so nothing about the endpoint says which of the two this is.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		built := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		code, result := f.send(t, upload(t, f.path, spdxInventory(built, "libc6")))
		if code != http.StatusAccepted {
			t.Fatalf("POST returned %d, want 202", code)
		}
		if result.Outcome != "queued" {
			t.Errorf("result is %+v", result)
		}
		// The document's own identity and its build time are what the arrival
		// decision turns on, and this format states both somewhere else.
		if result.BuiltAt != built.Format(time.RFC3339) {
			t.Errorf("reported build time %q, want %q", result.BuiltAt, built.Format(time.RFC3339))
		}
		if depth, _ := f.queue.Depth(t.Context()); depth != 1 {
			t.Errorf("%d jobs waiting, want 1", depth)
		}
	})
}

func TestAnInventoryWithNoBuildTimeIsRefused(t *testing.T) {
	// Taking it is worse than refusing it. The zero time is older than every
	// real one, so the first such upload is accepted and every later scan for
	// that target is refused as not newer — the target takes nothing further,
	// ever.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		undated := `{"bomFormat": "CycloneDX", "specVersion": "1.6",
		 "metadata": {"component": {"bom-ref": "root", "name": "p", "version": "1"}},
		 "components": [{"bom-ref": "a", "name": "libc", "version": "2.41"}]}`

		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, f.sending(upload(t, f.path, undated)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("an inventory with no build time returned %d, want 400", rec.Code)
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte("when it was built")) {
			t.Errorf("the refusal does not say what is missing: %s", rec.Body.String())
		}

		// And the target is not left wedged: a dated scan still lands.
		code, _ := f.send(t, upload(t, f.path, inventory(nowish(), "libc6")))
		if code != http.StatusAccepted {
			t.Errorf("a dated scan after an undated one returned %d", code)
		}
	})
}
