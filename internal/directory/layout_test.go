package directory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
)

// The standard's own examples of the filename rule, and the one it gives for
// the order the two steps run in.
//
// A rule taken from a specification is worth pinning against that
// specification's examples rather than against what this happens to produce:
// the filename is what a reader's tooling asks for by name, and it is wrong in
// a way nothing here can notice.
func TestADocumentIsNamedTheWayTheStandardNamesOne(t *testing.T) {
	for _, one := range []struct{ id, want string }{
		{"cisco-sa-20190513-secureboot", "cisco-sa-20190513-secureboot.json"},
		{"Example Company - 2019-YH3234", "example_company_-_2019-yh3234.json"},
		{"RHBA-2019:0024", "rhba-2019_0024.json"},
		// The standard's own worked example of why the lower-casing runs
		// first: applied the other way round, every capital would become an
		// underscore of its own and this would be "2022__01-a".
		{"2022_#01-A", "2022_01-a.json"},
	} {
		doc := &advisory.Document{}
		doc.Document.Tracking.ID = one.id
		doc.Document.Tracking.InitialReleaseDate = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
		if got := pathFor(doc); got != "2026/"+one.want {
			t.Errorf("%q is written to %q, want %q", one.id, got, "2026/"+one.want)
		}
	}
}

// The year folder is the year the flaw was recorded, not the year it was
// published. A document revised in January of the following year stays where
// its reader last found it.
func TestADocumentStaysInTheYearItWasRecordedIn(t *testing.T) {
	doc := &advisory.Document{}
	doc.Document.Tracking.ID = "EXNET-2025-0007"
	doc.Document.Tracking.InitialReleaseDate = time.Date(2025, 12, 31, 23, 0, 0, 0, time.UTC)
	doc.Document.Tracking.CurrentReleaseDate = time.Date(2026, 1, 2, 9, 0, 0, 0, time.UTC)
	if got := pathFor(doc); !strings.HasPrefix(got, "2025/") {
		t.Errorf("written to %q, want the 2025 folder", got)
	}
}

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
	if held != 1 {
		t.Errorf("held back %d, want the one that may not travel", held)
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
	if len(published) != 0 || held != 1 {
		t.Errorf("published %d and held %d, want none published", len(published), held)
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
