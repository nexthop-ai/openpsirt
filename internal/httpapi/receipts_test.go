package httpapi_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
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

// A run covers a build rather than an upload, so where one answers several the
// counts are reported against the newest of them. What the rest of the rows
// say about those counts is nothing — which has to read differently from a run
// that opened nothing, or an upload nothing was ever read from reads as a scan
// that found the build clean.
func TestCountsAreReportedOnceAndAZeroIsStillAnAnswer(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		names := catalog.NewStore(r.db.DB)
		located, err := names.Locate(ctx, "mine", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
		if err != nil {
			t.Fatal(err)
		}

		uploads := ingest.NewStore(r.db.DB)
		built := time.Now().UTC().Add(-6 * time.Hour)
		sent := 0
		// An upload as the endpoint leaves one: recorded, and its read marked
		// done, because an upload still in the queue reads as being read
		// whatever the runs around it did.
		file := func(t *testing.T, at time.Time) int64 {
			t.Helper()
			sent++
			scan, outcome, err := uploads.Record(ctx, ingest.Arriving{
				TargetID: target.ID, ContentHash: strconv.Itoa(sent),
				BuiltAt: at, ParserVersion: "test",
			})
			if err != nil || outcome != ingest.Accept {
				t.Fatalf("record upload %d: %v %v", sent, outcome, err)
			}
			if _, err := r.db.DB.NewUpdate().Model((*ingest.Scan)(nil)).
				Set("received_at = ?", at).Where("id = ?", scan.ID).
				Exec(ctx); err != nil {
				t.Fatal(err)
			}
			done := map[string]any{
				"kind": queue.Parse, "reference": strconv.FormatInt(scan.ID, 10),
				"state": queue.Done, "attempts": 1, "max_attempts": 5,
				"run_after": at, "created_at": at, "updated_at": at,
			}
			if _, err := r.db.DB.NewInsert().Model(&done).TableExpr("job").
				Exec(ctx); err != nil {
				t.Fatal(err)
			}
			return scan.ID
		}

		product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
		library := graph.Described{
			Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0",
		}
		// A run over what the newest upload described, finding the one issue.
		// A component no inventory placed opens no finding, so the graph is
		// applied from the upload the run is about.
		findings := finding.NewStore(r.db.DB)
		scan := func(t *testing.T, from int64, at time.Time) {
			t.Helper()
			if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, from, graph.Snapshot{
				Root:         product,
				Components:   []graph.Described{library},
				Dependencies: []graph.Dependency{{Parent: product, Child: library}},
			}); err != nil {
				t.Fatal(err)
			}
			run, err := findings.Begin(ctx, finding.Run{
				TargetID: target.ID, Scanner: "grype", RanHere: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{{
				Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
				Component: library,
			}}); err != nil {
				t.Fatal(err)
			}
			if err := findings.Finish(ctx, run.ID, "0.112.0", "2026-08-28", "", nil); err != nil {
				t.Fatal(err)
			}
			// When it ran, which is what decides the upload it answers and
			// the one its numbers are reported against.
			if _, err := r.db.DB.NewUpdate().Model((*finding.Run)(nil)).
				Set("started_at = ?", at.Add(-time.Minute)).Set("finished_at = ?", at).
				Where("id = ?", run.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		// Two uploads in one window, then the run that answers both.
		file(t, built.Add(time.Hour))
		scan(t, file(t, built.Add(2*time.Hour)), built.Add(3*time.Hour))

		var out httpapi.ReceiptsOutput
		path := "/v1/products/mine/streams/master/variants/broadcom/scans"
		read(t, r, "private-triage", path, &out.Body)
		if len(out.Body.Items) != 2 {
			t.Fatalf("got %d receipts, want the two that were sent", len(out.Body.Items))
		}
		newest, older := out.Body.Items[0], out.Body.Items[1]
		if newest.Opened == nil || *newest.Opened != 1 {
			t.Errorf("the upload the run is attributed to reports %s opened, want 1",
				shown(newest.Opened))
		}
		if older.Opened != nil || older.Closed != nil {
			t.Errorf("an upload whose run is reported on a newer receipt states %s and %s "+
				"rather than nothing", shown(older.Opened), shown(older.Closed))
		}

		// A third upload and a run over it that finds the same issue: nothing
		// opened, which is an answer and reads as one.
		scan(t, file(t, built.Add(4*time.Hour)), built.Add(5*time.Hour))
		read(t, r, "private-triage", path, &out.Body)
		if again := out.Body.Items[0]; again.Opened == nil || *again.Opened != 0 {
			t.Errorf("a run that opened nothing reports %s, want a stated zero",
				shown(again.Opened))
		}
	})
}

// shown is a count as a test failure should read it: the number, or the word
// for there not being one.
func shown(count *int) string {
	if count == nil {
		return "nothing"
	}
	return strconv.Itoa(*count)
}

// A pipeline key reaches the receipts for what it sent and reads no findings at
// all. What a run changed is a count of findings, so it is told nothing about
// it — which is not the same as being told the run changed nothing.
func TestAKeyThatReadsNoFindingsIsToldNothingAboutWhatARunChanged(t *testing.T) {
	twoIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		built := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		if code, _ := f.send(t, upload(t, f.path, inventory(built, "curl"))); code != http.StatusAccepted {
			t.Fatal("the upload was not taken")
		}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		reader := ingest.NewReader(f.db, f.queue, sbom.Limits{}, quiet, "test")
		if _, err := reader.Once(t.Context()); err != nil {
			t.Fatalf("reading: %v", err)
		}
		// A run over that upload, finished, so the receipt has one to report.
		var target int64
		if err := f.db.DB.NewSelect().TableExpr("target").Column("id").
			Limit(1).Scan(t.Context(), &target); err != nil {
			t.Fatal(err)
		}
		run := map[string]any{
			"target_id": target, "scanner": "test", "ran_here": true,
			"started_at": time.Now().UTC().Add(-time.Minute), "finished_at": time.Now().UTC(),
		}
		if _, err := f.db.DB.NewInsert().Model(&run).TableExpr("scan_run").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		_, out := receipts(t, f, f.key, f.path)
		if len(out.Body.Items) != 1 {
			t.Fatalf("got %d receipts, want the one that was sent", len(out.Body.Items))
		}
		got := out.Body.Items[0]
		if got.RunID == 0 {
			t.Fatal("the receipt names no run, so there is nothing to be told about")
		}
		if got.Opened != nil || got.Closed != nil {
			t.Errorf("a key that reads no findings is told the run opened %s and closed %s",
				shown(got.Opened), shown(got.Closed))
		}
	})
}
