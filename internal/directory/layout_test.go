// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
)

// The checksum answers for the file a reader fetched, which is a different
// question from the digest recorded against the issuance.
//
// Watched to move rather than asserted to exist: the moment a document was
// assembled is exactly what the settled digest leaves out, so a checksum taken
// over the settled form would be identical for two files that differ.
func TestTheChecksumIsOverTheBytesDeliveredAndNotOverWhatTheyState(t *testing.T) {
	doc := &advisory.Document{}
	doc.Document.Title = "A flaw in the recovery console"
	doc.Document.Tracking.ID = "EXNET-2026-0001"
	doc.Document.Tracking.CurrentReleaseDate = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	first, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	// One volatile field moved, and nothing the document states. The two are
	// the same advisory saying the same thing at two moments.
	doc.Document.Tracking.CurrentReleaseDate = time.Date(2026, 3, 4, 5, 6, 8, 0, time.UTC)
	second, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	was := checksum(entry{Body: first, Path: "2026/exnet-2026-0001.json"})
	now := checksum(entry{Body: second, Path: "2026/exnet-2026-0001.json"})
	if string(was) == string(now) {
		t.Errorf("the checksum did not move when the delivered bytes did: %s", was)
	}
	// And it names the file it answers for, after the two spaces the
	// command-line checker reads.
	if !strings.HasSuffix(string(was), "  exnet-2026-0001.json\n") {
		t.Errorf("the hash file does not name the document it is of: %q", was)
	}
	if strings.HasPrefix(string(was), " ") || len(strings.Fields(string(was))) != 2 {
		t.Errorf("the hash file does not start with the hash value: %q", was)
	}
}

// A document that may not be passed on is not written into the directory
// anybody may read, and the revision before it that may be is.
func TestAHeldBackRevisionIsNotPublishedAndTheOneBeforeItStillIs(t *testing.T) {
	published, held, err := publishable([]advisory.Sent{
		{Advisory: "EXNET-2026-0001", Ordinal: 2, Document: stated(t, "EXNET-2026-0001", "RED")},
		{Advisory: "EXNET-2026-0001", Ordinal: 1, Document: stated(t, "EXNET-2026-0001", "WHITE")},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is held back: the advisory is in the directory, under the
	// revision that may travel. Counted per revision walked past, this would
	// say one is missing from a directory that is missing none.
	if held != 0 {
		t.Errorf("held back %d, want none — the advisory is published", held)
	}
	if len(published) != 1 {
		t.Fatalf("published %d documents, want the revision that may travel", len(published))
	}
	if published[0].Summary != "WHITE" {
		t.Errorf("published the revision labeled %q", published[0].Summary)
	}
}

// A document that says nothing about how far it may travel is not read as
// permission to pass it on.
func TestADocumentWithNoLabelIsNotPublished(t *testing.T) {
	published, held, err := publishable([]advisory.Sent{
		{Advisory: "EXNET-2026-0002", Ordinal: 1, Document: stated(t, "EXNET-2026-0002", "")},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Held back, and counted: this advisory has gone out and the directory
	// carries no revision of it.
	if len(published) != 0 || held != 1 {
		t.Errorf("published %d and held %d, want none published and one held",
			len(published), held)
	}
}

// The list of changes is newest first, which is what lets a reader who
// fetched yesterday stop reading.
func TestTheListOfChangesIsNewestFirst(t *testing.T) {
	rows := strings.Split(strings.TrimSpace(string(changes([]entry{
		{Path: "2026/b.json", Released: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Path: "2026/c.json", Released: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)},
		{Path: "2026/a.json", Released: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
	}))), "\n")
	want := []string{"2026/c.json", "2026/a.json", "2026/b.json"}
	if len(rows) != len(want) {
		t.Fatalf("%d rows, want %d: %v", len(rows), len(want), rows)
	}
	for at := range want {
		if !strings.HasPrefix(rows[at], `"`+want[at]+`",`) {
			t.Errorf("row %d is %q, want %s first", at, rows[at], want[at])
		}
	}
}

// stated is a document that went out under one label, as the bytes that went
// out. The label is carried in the revision summary as well, so a test can say
// which of two revisions it is looking at.
func stated(t *testing.T, id, label string) string {
	t.Helper()
	doc := &advisory.Document{}
	doc.Document.Tracking.ID = id
	doc.Document.Tracking.InitialReleaseDate = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	doc.Document.Tracking.CurrentReleaseDate = time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	doc.Document.Tracking.RevisionHistory = []advisory.Revision{{
		Number: "1", Date: doc.Document.Tracking.InitialReleaseDate, Summary: label,
	}}
	if label != "" {
		doc.Document.Distribution = &advisory.Distribution{TLP: &advisory.TLP{Label: label}}
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
