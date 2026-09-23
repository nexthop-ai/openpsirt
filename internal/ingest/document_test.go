// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// aDocument is content large enough to span several rows, which is the case
// that matters: a document held in one row would never exercise the ordering
// or the reassembly.
func aDocument(size int) []byte {
	body := make([]byte, size)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	return body
}

func TestADocumentComesBackExactlyAsItArrived(t *testing.T) {
	// It is read back to be parsed and, for a tagged release, years later to
	// be re-scanned. A document that does not survive the round trip is a
	// release nobody can answer questions about.
	each(t, func(t *testing.T, s *ingest.Store, targetID int64) {
		ctx := t.Context()
		rec, outcome, err := s.Record(ctx, arriving(targetID, "hash-1", time.Now().UTC().Add(-time.Hour)))
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record: %v %v", outcome, err)
		}

		docs := ingest.NewDocuments(s.DB())
		body := aDocument(1_500_000)
		doc, err := docs.Write(ctx, rec.ID, ingest.InventoryKind, 0, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("write: %v", err)
		}

		if doc.SizeBytes != int64(len(body)) {
			t.Errorf("stored %d bytes, sent %d", doc.SizeBytes, len(body))
		}
		sum := sha256.Sum256(body)
		if doc.ContentHash != hex.EncodeToString(sum[:]) {
			t.Errorf("content hash is %q", doc.ContentHash)
		}

		got, err := io.ReadAll(docs.Open(ctx, doc.ID))
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("read back %d bytes, stored %d", len(got), len(body))
		}
	})
}

func TestAnEmptyDocumentIsStillADocument(t *testing.T) {
	// A build sending an empty part is sending something we should refuse for
	// a reason we can name, not something that reads back as content.
	each(t, func(t *testing.T, s *ingest.Store, targetID int64) {
		ctx := t.Context()
		rec, _, err := s.Record(ctx, arriving(targetID, "hash-1", time.Now().UTC().Add(-time.Hour)))
		if err != nil {
			t.Fatal(err)
		}
		docs := ingest.NewDocuments(s.DB())
		doc, err := docs.Write(ctx, rec.ID, ingest.InventoryKind, 0, strings.NewReader(""))
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if doc.SizeBytes != 0 {
			t.Errorf("an empty document stored %d bytes", doc.SizeBytes)
		}
		got, err := io.ReadAll(docs.Open(ctx, doc.ID))
		if err != nil || len(got) != 0 {
			t.Errorf("read back %d bytes, %v", len(got), err)
		}
	})
}

func TestASuppressionSetIsSeveralDocuments(t *testing.T) {
	// A build's suppressions are a directory rather than a file, so more than
	// one document of the same kind belongs to one scan.
	each(t, func(t *testing.T, s *ingest.Store, targetID int64) {
		ctx := t.Context()
		rec, _, err := s.Record(ctx, arriving(targetID, "hash-1", time.Now().UTC().Add(-time.Hour)))
		if err != nil {
			t.Fatal(err)
		}
		docs := ingest.NewDocuments(s.DB())
		if _, err := docs.Write(ctx, rec.ID, ingest.InventoryKind, 0, strings.NewReader("{}")); err != nil {
			t.Fatal(err)
		}
		for i := range 3 {
			if _, err := docs.Write(ctx, rec.ID, ingest.SuppressionsKind, i, strings.NewReader("{}")); err != nil {
				t.Fatal(err)
			}
		}
		held, err := docs.List(ctx, rec.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != 4 {
			t.Fatalf("held %d documents, want 4", len(held))
		}
		var suppressions int
		for _, doc := range held {
			if doc.Kind == ingest.SuppressionsKind {
				suppressions++
			}
		}
		if suppressions != 3 {
			t.Errorf("held %d suppression documents, want 3", suppressions)
		}
	})
}

func TestDiscardingLetsGoOfTheContentsAndKeepsTheRecord(t *testing.T) {
	// A nightly scan is superseded the next night, so its contents go:
	// keeping them grows storage with the calendar rather than with what
	// is tracked.
	//
	// The record of what arrived stays. It is a few hundred bytes against
	// tens of megabytes, and it carries the hash — which is what a
	// re-parse needs, because a re-parse means asking the build to send
	// the file again and the second copy is otherwise taken on trust.
	each(t, func(t *testing.T, s *ingest.Store, targetID int64) {
		ctx := t.Context()
		rec, _, err := s.Record(ctx, arriving(targetID, "hash-1", time.Now().UTC().Add(-time.Hour)))
		if err != nil {
			t.Fatal(err)
		}
		docs := ingest.NewDocuments(s.DB())
		doc, err := docs.Write(ctx, rec.ID, ingest.InventoryKind, 0, bytes.NewReader(aDocument(1_200_000)))
		if err != nil {
			t.Fatal(err)
		}

		if err := docs.Discard(ctx, rec.ID); err != nil {
			t.Fatalf("discard: %v", err)
		}
		held, err := docs.List(ctx, rec.ID)
		if err != nil || len(held) != 0 {
			t.Errorf("held %d documents after discarding, %v", len(held), err)
		}
		if got, _ := io.ReadAll(docs.Open(ctx, doc.ID)); len(got) != 0 {
			t.Errorf("%d bytes of content survived the discard", len(got))
		}

		// And what arrived is still answerable.
		sent, err := docs.Sent(ctx, []int64{rec.ID})
		if err != nil {
			t.Fatal(err)
		}
		if len(sent[rec.ID]) != 1 {
			t.Fatalf("the scan reads back as %d documents sent, want 1", len(sent[rec.ID]))
		}
		kept := sent[rec.ID][0]
		if kept.ContentHash != doc.ContentHash || kept.ContentHash == "" {
			t.Errorf("the hash of what arrived is %q, want %q", kept.ContentHash, doc.ContentHash)
		}
		if kept.SizeBytes != doc.SizeBytes {
			t.Errorf("what arrived reads back as %d bytes, want %d", kept.SizeBytes, doc.SizeBytes)
		}
		if kept.DiscardedAt == nil {
			t.Errorf("the record does not say the contents were let go")
		}
		// Discarding what is already gone is not an error: the retention sweep
		// and a re-run of it must agree.
		if err := docs.Discard(ctx, rec.ID); err != nil {
			t.Errorf("discarding twice: %v", err)
		}
	})
}
