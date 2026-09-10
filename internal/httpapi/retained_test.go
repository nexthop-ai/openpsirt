package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// Reading back a document a build sent.
//
// A tag's documents are retained precisely so a release can be re-scanned
// later, and nothing returned one — so "send me the SBOM you scanned for v2.4"
// was answered from the build system, which is the copy that may have moved.
func TestADocumentABuildSentReadsBackAsItArrived(t *testing.T) {
	twoIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		sent := inventory(nowish(), "libc6")
		code, result := f.send(t, upload(t, f.path, sent, suppression))
		if code != http.StatusAccepted {
			t.Fatalf("upload answered %d", code)
		}

		// What the receipt says arrived, which is where the identifiers come
		// from: a document is named through the scan it belongs to.
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, f.sending(httptest.NewRequest(http.MethodGet, f.path, nil)))
		if rec.Code != http.StatusOK {
			t.Fatalf("the receipts answered %d: %s", rec.Code, rec.Body.String())
		}
		var receipts struct {
			Items []struct {
				ScanID int64 `json:"scan_id"`
				Sent   []struct {
					DocumentID int64  `json:"document_id"`
					Kind       string `json:"kind"`
					SizeBytes  int64  `json:"size_bytes"`
					Held       bool   `json:"held"`
				} `json:"sent"`
			} `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &receipts); err != nil {
			t.Fatal(err)
		}
		if len(receipts.Items) != 1 || len(receipts.Items[0].Sent) != 2 {
			t.Fatalf("the receipt says it arrived with %+v", receipts.Items)
		}
		var inventoryID int64
		for _, doc := range receipts.Items[0].Sent {
			if doc.Kind == "inventory" {
				inventoryID = doc.DocumentID
				if doc.SizeBytes != int64(len(sent)) {
					t.Errorf("the receipt says %d bytes, %d were sent", doc.SizeBytes, len(sent))
				}
			}
			if !doc.Held {
				t.Errorf("a document was already let go: %+v", doc)
			}
		}
		if inventoryID == 0 {
			t.Fatal("the receipt named no inventory to read back")
		}

		at := func(scan, document int64) string {
			return f.path + "/" + itoa(scan) + "/documents/" + itoa(document)
		}
		// Byte for byte. The hash on the receipt is over what arrived, so
		// anything this rewrote would fail the one check the hash exists for.
		back := httptest.NewRecorder()
		f.handler.ServeHTTP(back, f.sending(
			httptest.NewRequest(http.MethodGet, at(result.ScanID, inventoryID), nil)))
		if back.Code != http.StatusOK {
			t.Fatalf("reading it back answered %d: %s", back.Code, back.Body.String())
		}
		if back.Body.String() != sent {
			t.Errorf("what came back is not what was sent:\n%s", back.Body.String())
		}

		// A second upload, so that "this scan's document" can be told from
		// "a document". Named through the first scan, the second scan's
		// document is not found — otherwise the path would be doing the
		// authorizing and the identifier would be doing the reading.
		later, second := f.send(t, upload(t, f.path, inventory(nowish().Add(time.Minute), "zlib")))
		if later != http.StatusAccepted {
			t.Fatalf("the second upload answered %d", later)
		}
		theirs := httptest.NewRecorder()
		f.handler.ServeHTTP(theirs, f.sending(httptest.NewRequest(http.MethodGet, f.path, nil)))
		var again struct {
			Items []struct {
				ScanID int64 `json:"scan_id"`
				Sent   []struct {
					DocumentID int64 `json:"document_id"`
				} `json:"sent"`
			} `json:"items"`
		}
		if err := json.Unmarshal(theirs.Body.Bytes(), &again); err != nil {
			t.Fatal(err)
		}
		var elsewhereID int64
		for _, item := range again.Items {
			if item.ScanID == second.ScanID && len(item.Sent) > 0 {
				elsewhereID = item.Sent[0].DocumentID
			}
		}
		if elsewhereID == 0 {
			t.Fatal("the second upload's document could not be found on its receipt")
		}
		crossed := httptest.NewRecorder()
		f.handler.ServeHTTP(crossed, f.sending(
			httptest.NewRequest(http.MethodGet, at(result.ScanID, elsewhereID), nil)))
		if crossed.Code != http.StatusNotFound {
			t.Errorf("another scan's document read through this one answered %d, wanted 404",
				crossed.Code)
		}

		// A document of another scan is not this scan's, and neither is one
		// that does not exist.
		for _, missing := range []struct {
			what           string
			scan, document int64
		}{
			{"a document that does not exist", result.ScanID, inventoryID + 9999},
			{"a scan that does not exist", result.ScanID + 9999, inventoryID},
		} {
			answer := httptest.NewRecorder()
			f.handler.ServeHTTP(answer, f.sending(
				httptest.NewRequest(http.MethodGet, at(missing.scan, missing.document), nil)))
			if answer.Code != http.StatusNotFound {
				t.Errorf("%s answered %d, wanted 404", missing.what, answer.Code)
			}
		}

		// Another credential reads back what it sent and nothing more, which
		// is the rule the receipts list applies. Answered as a scan that does
		// not exist, because telling the two apart is telling somebody what
		// exists elsewhere.
		_, secret, err := access.NewStore(f.db.DB).NewKey(context.Background(), "somebody-else",
			access.Scope{ProductID: productHere(t, f)})
		if err != nil {
			t.Fatal(err)
		}
		elsewhere := httptest.NewRequest(http.MethodGet, at(result.ScanID, inventoryID), nil)
		elsewhere.Header.Set("Authorization", "Bearer "+secret)
		other := httptest.NewRecorder()
		f.handler.ServeHTTP(other, elsewhere)
		if other.Code != http.StatusNotFound {
			t.Errorf("another key read back somebody else's upload with %d", other.Code)
		}

		// A branch build's contents are let go once they have been read, and
		// that answers as gone rather than as never having existed: the
		// receipt still says what arrived and what its bytes hashed to.
		if err := ingest.NewDocuments(f.db.DB).Discard(context.Background(), result.ScanID); err != nil {
			t.Fatal(err)
		}
		gone := httptest.NewRecorder()
		f.handler.ServeHTTP(gone, f.sending(
			httptest.NewRequest(http.MethodGet, at(result.ScanID, inventoryID), nil)))
		if gone.Code != http.StatusGone {
			t.Errorf("a document whose contents were let go answered %d, wanted 410", gone.Code)
		}
	})
}

// productHere is the product the ingest fixture declared.
func productHere(t *testing.T, f *ingestFixture) int64 {
	t.Helper()
	product, err := catalog.NewStore(f.db.DB).ProductByName(context.Background(), "sonic")
	if err != nil {
		t.Fatal(err)
	}
	return product.ID
}
