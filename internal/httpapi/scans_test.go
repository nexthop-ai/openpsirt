// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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

// spdx3Inventory is the same inventory again, in the version that states a
// document as one flat graph of typed elements.
func spdx3Inventory(builtAt time.Time, component string) string {
	return fmt.Sprintf(`{
	  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
	  "@graph": [
	    {"@id": "_:creationInfo", "type": "CreationInfo", "specVersion": "3.0.1", "created": %q},
	    {"spdxId": "https://example.invalid/sonic/%x", "type": "SpdxDocument",
	     "creationInfo": "_:creationInfo", "rootElement": ["urn:root"]},
	    {"spdxId": "urn:root", "type": "software_Package", "creationInfo": "_:creationInfo",
	     "name": "sonic-broadcom.bin", "software_packageVersion": "1.0"},
	    {"spdxId": "urn:a", "type": "software_Package", "creationInfo": "_:creationInfo",
	     "name": %q, "software_packageVersion": "2.41", "software_packageUrl": "pkg:deb/debian/%s@2.41"},
	    {"spdxId": "urn:rel", "type": "Relationship", "creationInfo": "_:creationInfo",
	     "from": "urn:root", "relationshipType": "dependsOn", "to": ["urn:a"]}
	  ]
	}`, builtAt.UTC().Format(time.RFC3339), builtAt.UnixNano(), component, component)
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

		depth, err := f.queue.Depth(t.Context(), queue.Parse)
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
		if depth, _ := f.queue.Depth(t.Context(), queue.Parse); depth != 1 {
			t.Errorf("%d jobs waiting after a repeat, want 1", depth)
		}
		docs, _ := ingest.NewDocuments(f.db.DB).List(t.Context(), first.ScanID)
		if len(docs) != 1 {
			t.Errorf("held %d documents after a repeat, want 1", len(docs))
		}
	})
}

// A second suppression document, differing from the first in the issue it
// argues about. Between two uploads of one inventory, a build's judgment about
// itself is what changes.
const secondSuppression = `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:y", "version": 1,
 "statements": [{"vulnerability": {"name": "CVE-2026-2"}, "status": "not_affected",
 "products": [{"@id": "pkg:deb/debian/libc6"}]}]}`

func TestAnUnchangedInventoryWithChangedJudgmentsIsTaken(t *testing.T) {
	// A build whose contents have not moved and which has since worked out
	// that three issues do not apply to it re-sends the same inventory with
	// different claims beside it. Hashing the inventory alone answers 200 and
	// drops the claims, so the findings the build has already answered stay
	// open behind a success.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		built := nowish()
		body := inventory(built, "libc6")

		code, first := f.send(t, upload(t, f.path, body, suppression))
		if code != http.StatusAccepted {
			t.Fatalf("first upload returned %d, want 202", code)
		}
		code, again := f.send(t, upload(t, f.path, body, secondSuppression))
		if code != http.StatusAccepted {
			t.Fatalf("the same inventory with changed claims returned %d, want 202", code)
		}
		if again.Outcome != "queued" || again.ScanID == first.ScanID {
			t.Fatalf("second upload reported %+v, want a scan of its own", again)
		}

		// The claims arrived with a scan and are stored against it, so the
		// second submission has to be work of its own: applied to the first
		// scan, the record would say that upload carried arguments it did not
		// carry.
		docs, err := ingest.NewDocuments(f.db.DB).List(t.Context(), again.ScanID)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 2 {
			t.Errorf("held %d documents for the second submission, want an inventory and its claims", len(docs))
		}
		if depth, _ := f.queue.Depth(t.Context(), queue.Parse); depth != 2 {
			t.Errorf("%d jobs waiting, want one per submission", depth)
		}
	})
}

func TestTheWholeSubmissionSentAgainIsStillOneWeHold(t *testing.T) {
	// The same documents in a different part order is the same submission:
	// the claim digests are sorted before they are folded together, so a
	// pipeline that builds its request from a directory listing is not
	// answered as though the build had changed its mind.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		built := nowish()
		body := inventory(built, "libc6")

		code, first := f.send(t, upload(t, f.path, body, suppression, secondSuppression))
		if code != http.StatusAccepted {
			t.Fatalf("first upload returned %d, want 202", code)
		}
		code, again := f.send(t, upload(t, f.path, body, secondSuppression, suppression))
		if code != http.StatusOK {
			t.Fatalf("the same submission reordered returned %d, want 200", code)
		}
		if again.Outcome != "already_held" || again.ScanID != first.ScanID {
			t.Errorf("second upload reported %+v, want the first scan %d", again, first.ScanID)
		}
		if depth, _ := f.queue.Depth(t.Context(), queue.Parse); depth != 1 {
			t.Errorf("%d jobs waiting after a repeat, want 1", depth)
		}
	})
}

func TestBytesThatCouldNotBeReadAreTakenAgain(t *testing.T) {
	// An upload that was accepted and then failed to parse still counted as
	// one we hold, so the identical bytes could never be sent again however
	// the reason they could not be read was put right.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		built := nowish()
		body := inventory(built, "libc6")

		code, first := f.send(t, upload(t, f.path, body, suppression))
		if code != http.StatusAccepted {
			t.Fatalf("first upload returned %d, want 202", code)
		}
		scans := ingest.NewStore(f.db.DB)
		if err := scans.MarkFailed(t.Context(), first.ScanID, fmt.Errorf("the reader fell over")); err != nil {
			t.Fatal(err)
		}

		code, again := f.send(t, upload(t, f.path, body, suppression))
		if code != http.StatusAccepted {
			t.Fatalf("the same bytes after a failure returned %d, want 202", code)
		}
		// The same row: one set of bytes at one build is one submission, and
		// what changes is which attempt at it is the live one.
		if again.ScanID != first.ScanID || again.Outcome != "queued" {
			t.Errorf("the retake reported %+v, want scan %d queued", again, first.ScanID)
		}
		held, err := scans.ByID(t.Context(), first.ScanID)
		if err != nil {
			t.Fatal(err)
		}
		if held.Status != ingest.Accepted || held.Failure != "" {
			t.Errorf("the scan reads as %q: %q", held.Status, held.Failure)
		}
		// One inventory, not two. A second copy is one the reader would read
		// and count twice.
		docs, err := ingest.NewDocuments(f.db.DB).List(t.Context(), first.ScanID)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 2 {
			t.Errorf("held %d documents after the retake, want an inventory and its claims", len(docs))
		}
		if depth, _ := f.queue.Depth(t.Context(), queue.Parse); depth != 2 {
			t.Errorf("%d jobs waiting, want the first and the one that will read it again", depth)
		}
	})
}

func TestBytesThatCouldNotBeReadAreTakenAgainBesideAnAcceptedScan(t *testing.T) {
	// The retake with something already accepted at that build time, which is
	// the arrangement the re-argued arm produces: one submission of a build
	// lands and is read, a second with different judgments lands and fails to
	// parse, and the producer re-sends it once the reader is fixed.
	//
	// Taken as a new scan, the insert collides with the row those bytes
	// already have and the producer is answered success pointing at a scan
	// that still reads failed — with nothing stored and nothing queued.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		built := nowish()
		body := inventory(built, "libc6")

		code, first := f.send(t, upload(t, f.path, body, suppression))
		if code != http.StatusAccepted {
			t.Fatalf("first upload returned %d, want 202", code)
		}
		code, second := f.send(t, upload(t, f.path, body, secondSuppression))
		if code != http.StatusAccepted {
			t.Fatalf("the same inventory re-argued returned %d, want 202", code)
		}
		scans := ingest.NewStore(f.db.DB)
		if err := scans.MarkFailed(t.Context(), second.ScanID, fmt.Errorf("the reader fell over")); err != nil {
			t.Fatal(err)
		}

		code, again := f.send(t, upload(t, f.path, body, secondSuppression))
		if code != http.StatusAccepted {
			t.Fatalf("the same bytes after a failure returned %d, want 202", code)
		}
		if again.ScanID != second.ScanID {
			t.Errorf("the retake reported scan %d, want the row those bytes already have (%d)",
				again.ScanID, second.ScanID)
		}
		held, err := scans.ByID(t.Context(), second.ScanID)
		if err != nil {
			t.Fatal(err)
		}
		if held.Status != ingest.Accepted || held.Failure != "" {
			t.Errorf("the scan reads as %q: %q", held.Status, held.Failure)
		}
		docs, err := ingest.NewDocuments(f.db.DB).List(t.Context(), second.ScanID)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 2 {
			t.Errorf("held %d documents after the retake, want an inventory and its claims", len(docs))
		}
		if depth, _ := f.queue.Depth(t.Context(), queue.Parse); depth != 3 {
			t.Errorf("%d jobs waiting, want one per submission and one to read it again", depth)
		}
		// And the build stands on the retaken submission, not on the one
		// before it: they share a build time, and what settles a tie is which
		// arrived last.
		if first.ScanID == second.ScanID {
			t.Fatal("the two submissions became one scan")
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

func TestAnUploadInTheThirdSpdxVersionIsTaken(t *testing.T) {
	// The version that puts the header inside the contents. The arrival
	// decision turns on the document's identity and its build time, and this
	// format states both as entries of the same array its packages are in —
	// so the pass that answers those has more to walk, and answers the same
	// two questions.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		built := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		code, result := f.send(t, upload(t, f.path, spdx3Inventory(built, "libc6")))
		if code != http.StatusAccepted {
			t.Fatalf("POST returned %d, want 202", code)
		}
		if result.BuiltAt != built.Format(time.RFC3339) {
			t.Errorf("reported build time %q, want %q", result.BuiltAt, built.Format(time.RFC3339))
		}
		if depth, _ := f.queue.Depth(t.Context(), queue.Parse); depth != 1 {
			t.Errorf("%d jobs waiting, want 1", depth)
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
		if depth, _ := f.queue.Depth(t.Context(), queue.Parse); depth != 1 {
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

// TestEveryDoorThatTurnsAnUploadAwayRecordsIt holds the line that a refusal is
// recorded whichever way the upload was refused.
//
// The record exists so the coverage report can tell a build nobody uploads to
// from one whose uploads are being turned away. Wired to one arm it told the
// wrong story about the other: a producer posting a document nothing can read —
// the commoner of the two failures the table was made for — still drew as
// quiet-and-never-refused, which reads as a pipeline nobody wired up.
//
// Through the door rather than against the store, because that is where the
// arms are and the store was never the part that was missing.
func TestEveryDoorThatTurnsAnUploadAwayRecordsIt(t *testing.T) {
	for _, c := range []struct {
		what string
		body string
		want int
	}{
		{"a document nothing can read", "{ not an inventory", http.StatusUnprocessableEntity},
		{"one that does not say when it was built", inventory(time.Time{}, "libc6"), http.StatusBadRequest},
	} {
		t.Run(c.what, func(t *testing.T) {
			eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
				if code, _ := f.send(t, upload(t, f.path, c.body)); code != c.want {
					t.Fatalf("%s answered %d, want %d", c.what, code, c.want)
				}
				var recorded []struct {
					Reason string `bun:"reason"`
				}
				if err := f.db.DB.NewSelect().Table("scan_refusal").
					Column("reason").Scan(t.Context(), &recorded); err != nil {
					t.Fatal(err)
				}
				if len(recorded) != 1 {
					t.Fatalf("%s left %d refusals behind, want one", c.what, len(recorded))
				}
				// The words the producer was given, so both ends of the
				// conversation say the same thing when somebody compares them.
				if recorded[0].Reason == "" {
					t.Errorf("%s recorded a refusal with no reason", c.what)
				}
			})
		})
	}
}
