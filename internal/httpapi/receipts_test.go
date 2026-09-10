package httpapi_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// receipts asks what became of what was filed, as whoever holds secret.
func receipts(t *testing.T, f *ingestFixture, secret, path string) (int, httpapi.ReceiptsOutput) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	var out httpapi.ReceiptsOutput
	if rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out.Body); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func TestASenderReadsBackWhatBecameOfWhatItSent(t *testing.T) {
	// An upload is answered before its documents are read, so the acceptance
	// says nothing about whether they parsed. Without this the only party who
	// can fix a producer emitting unreadable files sees a success every night.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		if code, _ := f.send(t, upload(t, f.path, inventory(nowish(), "libc6"))); code != http.StatusAccepted {
			t.Fatalf("upload returned %d", code)
		}

		code, out := receipts(t, f, f.key, f.path)
		if code != http.StatusOK {
			t.Fatalf("reading receipts returned %d", code)
		}
		if out.Body.Total != 1 || len(out.Body.Items) != 1 {
			t.Fatalf("got %d receipts (total %d), want 1", len(out.Body.Items), out.Body.Total)
		}
		if got := out.Body.Items[0].State; got != string(ingest.Reading) {
			t.Errorf("before the work ran the state is %q, want %q", got, ingest.Reading)
		}

		// Once it has been read there is nothing left to say about parsing,
		// and what remains is the vulnerability scan.
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		reader := ingest.NewReader(f.db, f.queue, sbom.Limits{}, quiet, "test")
		if _, err := reader.Once(t.Context()); err != nil {
			t.Fatalf("reading: %v", err)
		}
		_, out = receipts(t, f, f.key, f.path)
		if got := out.Body.Items[0].State; got != string(ingest.Scanning) {
			t.Errorf("after reading the state is %q, want %q", got, ingest.Scanning)
		}
		if out.Body.Items[0].Failure != "" {
			t.Errorf("a scan that read cleanly reports %q", out.Body.Items[0].Failure)
		}
	})
}

func TestAnUnreadableUploadSaysSoToWhoeverSentIt(t *testing.T) {
	// The producer's own text back at them. A file this deployment cannot use
	// is the producer's to fix, so it is reported rather than logged away.
	twoIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		// Well-formed enough to be taken, and unusable: a component with no
		// name cannot be identified, so it cannot be tracked.
		nameless := `{
		  "bomFormat": "CycloneDX", "specVersion": "1.6",
		  "metadata": {"timestamp": "` + nowish().Format(time.RFC3339) + `",
		    "component": {"bom-ref": "root", "name": "sonic-broadcom.bin", "version": "1.0"}},
		  "components": [{"bom-ref": "a", "version": "2.41"}],
		  "dependencies": [{"ref": "root", "dependsOn": ["a"]}]
		}`
		if code, _ := f.send(t, upload(t, f.path, nameless)); code != http.StatusAccepted {
			t.Fatalf("upload returned %d", code)
		}

		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		reader := ingest.NewReader(f.db, f.queue, sbom.Limits{}, quiet, "test")
		// The read fails; that is the point. What matters is what it leaves
		// behind for the sender to read.
		_, _ = reader.Once(t.Context())

		_, out := receipts(t, f, f.key, f.path)
		if len(out.Body.Items) != 1 {
			t.Fatalf("got %d receipts, want 1", len(out.Body.Items))
		}
		if got := out.Body.Items[0].State; got != string(ingest.Refused) {
			t.Fatalf("state is %q, want %q", got, ingest.Refused)
		}
		if out.Body.Items[0].Failure == "" {
			t.Error("a refusal that does not say why leaves the sender no better off")
		}
	})
}

func TestASenderIsToldNothingOfAnotherSendersUploads(t *testing.T) {
	// Two pipelines on one product is the expected arrangement, and a key
	// reading back the whole product's upload history would be a report about
	// the product rather than a receipt for its own work. The count has to
	// narrow with the list: a total covering rows nobody was shown says how
	// many other builds there are.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		ctx := t.Context()
		rights := access.NewStore(f.db.DB)
		product, err := catalog.NewStore(f.db.DB).ProductByName(ctx, "sonic")
		if err != nil {
			t.Fatal(err)
		}
		_, other, err := rights.NewKey(ctx, "nightly-other", access.Scope{ProductID: product.ID})
		if err != nil {
			t.Fatal(err)
		}

		if code, _ := f.send(t, upload(t, f.path, inventory(nowish(), "libc6"))); code != http.StatusAccepted {
			t.Fatalf("first upload returned %d", code)
		}
		req := upload(t, f.path, inventory(nowish().Add(time.Minute), "zlib1g"))
		req.Header.Set("Authorization", "Bearer "+other)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("second upload returned %d: %s", rec.Code, rec.Body.String())
		}

		for _, who := range []struct {
			name   string
			secret string
		}{{"nightly", f.key}, {"nightly-other", other}} {
			_, out := receipts(t, f, who.secret, f.path)
			if len(out.Body.Items) != 1 {
				t.Errorf("%s was shown %d uploads, want only its own", who.name, len(out.Body.Items))
			}
			if out.Body.Total != 1 {
				t.Errorf("%s was told the total is %d, which counts uploads it was not shown",
					who.name, out.Body.Total)
			}
		}
	})
}

func TestAPinnedKeyReadsNoWiderThanItSends(t *testing.T) {
	// A key's scope is a set of constraints, and every one present must match.
	// Reading back is authorized the same way sending is, or a key pinned to
	// one variant would report on every other.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		ctx := t.Context()
		cat := catalog.NewStore(f.db.DB)
		product, err := cat.ProductByName(ctx, "sonic")
		if err != nil {
			t.Fatal(err)
		}
		mellanox, err := cat.DeclareVariant(ctx, product.ID, "mellanox", true)
		if err != nil {
			t.Fatal(err)
		}
		rights := access.NewStore(f.db.DB)
		_, pinned, err := rights.NewKey(ctx, "mellanox-only",
			access.Scope{ProductID: product.ID, VariantID: &mellanox.ID})
		if err != nil {
			t.Fatal(err)
		}

		if code, _ := f.send(t, upload(t, f.path, inventory(nowish(), "libc6"))); code != http.StatusAccepted {
			t.Fatalf("upload returned %d", code)
		}
		if code, _ := receipts(t, f, pinned, f.path); code != http.StatusForbidden {
			t.Errorf("a key pinned to another variant read these receipts: %d", code)
		}

		// The same pin, in the direction it was written for. A mismatch is
		// refused rather than redirected: filing one variant's inventory under
		// another's name is worse than a failed build, because the build goes
		// green and two variants are then both wrong.
		req := upload(t, f.path, inventory(nowish().Add(time.Minute), "zlib1g"))
		req.Header.Set("Authorization", "Bearer "+pinned)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("a key pinned to another variant filed against this one: %d", rec.Code)
		}
		if _, out := receipts(t, f, f.key, f.path); out.Body.Total != 1 {
			t.Errorf("%d scans were filed against this variant, want the one that was authorized",
				out.Body.Total)
		}
	})
}

func TestAReceiptSaysWhatArrivedAfterTheContentsAreGone(t *testing.T) {
	// A branch build's contents are let go once they have been read,
	// because the next night supersedes them. What arrived is still
	// answerable: what kind of document, how large, and what its bytes
	// hashed to.
	//
	// The hash is the point. A re-parse means asking the build to send the
	// file again, and without something to compare against the second copy
	// is taken on trust — so a receipt that forgot what it had read left
	// the producer no way to prove it was sending back the same file.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		if code, _ := f.send(t, upload(t, f.path,
			inventory(nowish(), "libc6"), suppression, suppression)); code != http.StatusAccepted {
			t.Fatal("the upload was not taken")
		}

		// Before it is read, everything is held.
		_, out := receipts(t, f, f.key, f.path)
		if len(out.Body.Items) != 1 {
			t.Fatalf("got %d receipts, want 1", len(out.Body.Items))
		}
		sent := out.Body.Items[0].Sent
		if len(sent) != 3 {
			t.Fatalf("the upload reads back as %d documents, want 3 (an inventory and two "+
				"suppressions)", len(sent))
		}
		for _, doc := range sent {
			if !doc.Held {
				t.Errorf("a %s document is reported let go before anything read it", doc.Kind)
			}
		}

		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		reader := ingest.NewReader(f.db, f.queue, sbom.Limits{}, quiet, "test")
		if _, err := reader.Once(t.Context()); err != nil {
			t.Fatalf("reading: %v", err)
		}

		_, out = receipts(t, f, f.key, f.path)
		after := out.Body.Items[0].Sent
		if len(after) != len(sent) {
			t.Fatalf("after reading, the upload reads back as %d documents, want %d",
				len(after), len(sent))
		}
		for i, doc := range after {
			if doc.Held {
				t.Errorf("a %s document of a branch build is still held after it was read", doc.Kind)
			}
			if doc.Hash == "" || doc.Hash != sent[i].Hash {
				t.Errorf("the %s document hashes to %q, want %q", doc.Kind, doc.Hash, sent[i].Hash)
			}
			if doc.SizeBytes != sent[i].SizeBytes || doc.SizeBytes == 0 {
				t.Errorf("the %s document reads back as %d bytes, want %d",
					doc.Kind, doc.SizeBytes, sent[i].SizeBytes)
			}
		}
	})
}

func TestAReceiptSaysHowMuchOfAnInventoryWasPlaced(t *testing.T) {
	// The pair is what says whether an inventory is a graph or a list. A
	// document that places none of its components produces findings that are
	// each correct and cannot answer "why is this here" about any of them —
	// and until this was on the receipt, the only record of it was a log line
	// somebody would have to go and find.
	//
	// One unplaced component is ordinary and a producer emitting none of the
	// edges is not. Only the ratio tells them apart.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		// Two components and one edge between them, so something is placed and
		// something is not: a flat list and a full graph both read as "fine"
		// against a single number.
		flat := `{
		  "bomFormat": "CycloneDX", "specVersion": "1.6",
		  "metadata": {"timestamp": "` + nowish().Format(time.RFC3339) + `",
		    "component": {"bom-ref": "root", "name": "sonic-broadcom", "version": "1.0"}},
		  "components": [
		    {"bom-ref": "a", "name": "placed-under-root", "version": "1.0",
		     "purl": "pkg:deb/debian/placed-under-root@1.0"},
		    {"bom-ref": "b", "name": "placed-nowhere", "version": "2.0",
		     "purl": "pkg:deb/debian/placed-nowhere@2.0"}
		  ],
		  "dependencies": [{"ref": "root", "dependsOn": ["a"]}]
		}`
		if code, _ := f.send(t, upload(t, f.path, flat)); code != http.StatusAccepted {
			t.Fatal("the upload was not taken")
		}

		// Before it is read, nothing is claimed about it: an upload is bytes,
		// and how much of it is placed is an answer the parser produces.
		_, out := receipts(t, f, f.key, f.path)
		if len(out.Body.Items) != 1 {
			t.Fatalf("got %d receipts, want 1", len(out.Body.Items))
		}
		if out.Body.Items[0].Components != nil || out.Body.Items[0].Placed != nil {
			t.Errorf("an upload nothing has read already claims what it is made of: %+v",
				out.Body.Items[0])
		}

		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		reader := ingest.NewReader(f.db, f.queue, sbom.Limits{}, quiet, "test")
		if _, err := reader.Once(t.Context()); err != nil {
			t.Fatalf("reading: %v", err)
		}

		_, out = receipts(t, f, f.key, f.path)
		got := out.Body.Items[0]
		if got.Components == nil || got.Placed == nil {
			t.Fatalf("after reading, the receipt says nothing about what it was made of: %+v", got)
		}
		if *got.Components != 2 {
			t.Errorf("the inventory reads as %d components, want 2", *got.Components)
		}
		if *got.Placed != 1 {
			t.Errorf("%d components read as placed, want the one an edge leads to", *got.Placed)
		}
	})
}
