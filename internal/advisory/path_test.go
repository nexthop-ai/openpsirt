package advisory_test

import (
	"path"
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
		if got := advisory.PathFor(doc); got != "2026/"+one.want {
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
	if got := advisory.PathFor(doc); !strings.HasPrefix(got, "2025/") {
		t.Errorf("written to %q, want the 2025 folder", got)
	}
}

// A document states where it is published, and states it only where the
// deployment knows where that is.
//
// A reader's tooling follows a self reference, so one pointing at an address
// that answers nothing is worse than none — and the address it states has to
// be the file the directory writes rather than a second guess at it.
func TestADocumentStatesItsOwnAddressWhereThereIsOne(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)

		// A deployment that has not said where its documents are reachable
		// states nothing about where this one is.
		doc, err := f.document(t, "sonic", identifier)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if at := selfReferenceIn(doc); at != "" {
			t.Errorf("a document nobody publishes cites itself at %q", at)
		}

		// One that has states it, at the file the directory writes.
		publishing := issuer
		publishing.Published = "https://psirt.example.test/.well-known/csaf/"
		made, err := f.store.Mint(t.Context(), f.who, publishing, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Add(t.Context(), f.who, made.Identifier,
			"sonic", identifier); err != nil {
			t.Fatal(err)
		}
		doc, err = f.store.ForAdvisory(t.Context(), f.who, publishing, made.Identifier)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		want := publishing.Published + advisory.PathFor(doc)
		at := selfReferenceIn(doc)
		if at != want {
			t.Errorf("the document cites itself at %q, want %q", at, want)
		}
		// The three clauses the standard's own test asks for, stated here
		// rather than inferred from the address matching what this package
		// computes: a change that moved both would leave that comparison
		// passing and the document without a canonical URL.
		if !strings.HasPrefix(at, "https://") {
			t.Errorf("the address it cites is not over TLS: %q", at)
		}
		_, name := path.Split(advisory.PathFor(doc))
		if !strings.HasSuffix(at, name) {
			t.Errorf("the address it cites does not end at the document's filename %q: %q",
				name, at)
		}
		if !strings.HasSuffix(name, ".json") {
			t.Errorf("the filename is not a document's: %q", name)
		}
		// And it is the last of them: the others are where a reader goes to
		// read about the flaw, and this one is where they already are.
		last := doc.Document.References[len(doc.Document.References)-1]
		if last.Category != "self" {
			t.Errorf("the last reference is %+v, want the document's own address", last)
		}
	})
}

// selfReferenceIn is the address a document states for itself, or nothing
// where it states none.
func selfReferenceIn(doc *advisory.Document) string {
	for _, one := range doc.Document.References {
		if one.Category == "self" {
			return one.URL
		}
	}
	return ""
}
