// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// Reading back a document a build sent.
//
// A tag's documents are retained precisely so a release can be re-scanned
// later, and nothing returned one — so "send me the SBOM you scanned for v2.4"
// was answered from the build system, which is the copy that may have moved.
func TestADocumentABuildSentReadsBackAsItArrived(t *testing.T) {
	twoIngest(t, queue.DefaultOptions(), func(t *testing.T, f *httpapitest.IngestFixture) {
		sent := httpapitest.Inventory(httpapitest.Nowish(), "libc6")
		code, result := f.Send(t, httpapitest.Upload(t, f.Path, sent, suppression))
		if code != http.StatusAccepted {
			t.Fatalf("upload answered %d", code)
		}

		// The receipt's own record of what arrived, which is where the
		// identifiers come from: a document is named through the scan it
		// belongs to.
		rec := httptest.NewRecorder()
		f.Handler.ServeHTTP(rec, f.Sending(httptest.NewRequest(http.MethodGet, f.Path, nil)))
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
			return f.Path + "/" + httpapitest.Itoa(scan) + "/documents/" + httpapitest.Itoa(document)
		}
		// Byte for byte. The hash on the receipt is over what arrived, so
		// anything this rewrote would fail the one check the hash exists for.
		back := httptest.NewRecorder()
		f.Handler.ServeHTTP(back, f.Sending(
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
		later, second := f.Send(t, httpapitest.Upload(t, f.Path, httpapitest.Inventory(httpapitest.Nowish().Add(time.Minute), "zlib")))
		if later != http.StatusAccepted {
			t.Fatalf("the second upload answered %d", later)
		}
		theirs := httptest.NewRecorder()
		f.Handler.ServeHTTP(theirs, f.Sending(httptest.NewRequest(http.MethodGet, f.Path, nil)))
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
		f.Handler.ServeHTTP(crossed, f.Sending(
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
			f.Handler.ServeHTTP(answer, f.Sending(
				httptest.NewRequest(http.MethodGet, at(missing.scan, missing.document), nil)))
			if answer.Code != http.StatusNotFound {
				t.Errorf("%s answered %d, wanted 404", missing.what, answer.Code)
			}
		}

		// Another key that may upload to this build reads back what was filed
		// on it, whoever sent it, which is the rule the receipts list applies.
		_, secret, err := access.NewStore(f.DB.DB).NewKey(context.Background(), "somebody-else",
			access.Scope{ProductID: httpapitest.ProductHere(t, f)})
		if err != nil {
			t.Fatal(err)
		}
		elsewhere := httptest.NewRequest(http.MethodGet, at(result.ScanID, inventoryID), nil)
		elsewhere.Header.Set("Authorization", "Bearer "+secret)
		other := httptest.NewRecorder()
		f.Handler.ServeHTTP(other, elsewhere)
		if other.Code != http.StatusOK {
			t.Errorf("another key on the build could not read back an upload filed there: %d",
				other.Code)
		}

		// A key pinned to another variant of the product reaches the product
		// and not this build, and is refused for the act.
		variant, err := catalog.NewStore(f.DB.DB).DeclareVariant(context.Background(),
			httpapitest.ProductHere(t, f), "elsewhere", true)
		if err != nil {
			t.Fatal(err)
		}
		_, pinned, err := access.NewStore(f.DB.DB).NewKey(context.Background(), "pinned-elsewhere",
			access.Scope{ProductID: httpapitest.ProductHere(t, f), VariantID: &variant.ID})
		if err != nil {
			t.Fatal(err)
		}
		fenced := httptest.NewRequest(http.MethodGet, at(result.ScanID, inventoryID), nil)
		fenced.Header.Set("Authorization", "Bearer "+pinned)
		refused := httptest.NewRecorder()
		f.Handler.ServeHTTP(refused, fenced)
		httpapitest.RefusedWith(t, refused, http.StatusForbidden)

		// A branch build's contents are let go once they have been read, and
		// that answers as gone rather than as never having existed: the
		// receipt still says what arrived and what its bytes hashed to.
		if err := ingest.NewDocuments(f.DB.DB).Discard(context.Background(), result.ScanID); err != nil {
			t.Fatal(err)
		}
		gone := httptest.NewRecorder()
		f.Handler.ServeHTTP(gone, f.Sending(
			httptest.NewRequest(http.MethodGet, at(result.ScanID, inventoryID), nil)))
		if gone.Code != http.StatusGone {
			t.Errorf("a document whose contents were let go answered %d, wanted 410", gone.Code)
		}
	})
}

func TestARetainedDocumentIsNamedByItsEncoding(t *testing.T) {
	// A copy named for the other encoding is misread by anything that opens it
	// by its extension: a validator, an editor, somebody double-clicking it.
	twoIngest(t, queue.DefaultOptions(), func(t *testing.T, f *httpapitest.IngestFixture) {
		for i, tc := range []struct {
			sent, named string
		}{
			{httpapitest.Inventory(httpapitest.Nowish(), "libc6"), ".json"},
			{cyclonedxXMLInventory(httpapitest.Nowish().Add(time.Minute), "zlib"), ".xml"},
		} {
			code, result := f.Send(t, httpapitest.Upload(t, f.Path, tc.sent))
			if code != http.StatusAccepted {
				t.Fatalf("upload %d answered %d", i, code)
			}
			inventoryID := sentInventory(t, f, result.ScanID)
			back := httptest.NewRecorder()
			f.Handler.ServeHTTP(back, f.Sending(httptest.NewRequest(http.MethodGet,
				f.Path+"/"+httpapitest.Itoa(result.ScanID)+"/documents/"+httpapitest.Itoa(inventoryID), nil)))
			if back.Code != http.StatusOK {
				t.Fatalf("reading upload %d back answered %d: %s", i, back.Code, back.Body.String())
			}
			// Looking at the first character to name it takes nothing away
			// from what is sent.
			if back.Body.String() != tc.sent {
				t.Errorf("what came back of upload %d is not what was sent", i)
			}
			want := "attachment; filename=\"inventory-" + httpapitest.Itoa(inventoryID) + tc.named + "\""
			if got := back.Header().Get("Content-Disposition"); got != want {
				t.Errorf("upload %d is named %q, want %q", i, got, want)
			}
		}
	})
}

func TestADocumentLetGoAsItIsReadAnswersGone(t *testing.T) {
	// Its record still says it is held and its parts are gone, which is what
	// a reader meets when the contents are let go between the two. The first
	// character is looked at before anything is sent, so this is answered as
	// gone rather than as a transfer that stops short.
	twoIngest(t, queue.DefaultOptions(), func(t *testing.T, f *httpapitest.IngestFixture) {
		code, result := f.Send(t, httpapitest.Upload(t, f.Path,
			httpapitest.Inventory(httpapitest.Nowish(), "libc6")))
		if code != http.StatusAccepted {
			t.Fatalf("upload answered %d", code)
		}
		inventoryID := sentInventory(t, f, result.ScanID)
		if _, err := f.DB.ExecContext(context.Background(),
			`DELETE FROM "scan_document_chunk" WHERE "document_id" = ?`, inventoryID); err != nil {
			t.Fatal(err)
		}
		gone := httptest.NewRecorder()
		f.Handler.ServeHTTP(gone, f.Sending(httptest.NewRequest(http.MethodGet,
			f.Path+"/"+httpapitest.Itoa(result.ScanID)+"/documents/"+httpapitest.Itoa(inventoryID), nil)))
		if gone.Code != http.StatusGone {
			t.Errorf("a document let go as it was read answered %d, wanted 410: %s",
				gone.Code, gone.Body.String())
		}
	})
}

// sentInventory is the inventory a scan arrived with, as its receipt names it.
func sentInventory(t *testing.T, f *httpapitest.IngestFixture, scan int64) int64 {
	t.Helper()
	rec := httptest.NewRecorder()
	f.Handler.ServeHTTP(rec, f.Sending(httptest.NewRequest(http.MethodGet, f.Path, nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("the receipts answered %d: %s", rec.Code, rec.Body.String())
	}
	var receipts struct {
		Items []struct {
			ScanID int64 `json:"scan_id"`
			Sent   []struct {
				DocumentID int64  `json:"document_id"`
				Kind       string `json:"kind"`
			} `json:"sent"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &receipts); err != nil {
		t.Fatal(err)
	}
	for _, item := range receipts.Items {
		for _, doc := range item.Sent {
			if item.ScanID == scan && doc.Kind == "inventory" {
				return doc.DocumentID
			}
		}
	}
	t.Fatalf("no receipt names the inventory scan %d arrived with", scan)
	return 0
}
