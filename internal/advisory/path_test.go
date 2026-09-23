// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory_test

import (
	"encoding/json"
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

// A second issuance landing between a document being assembled and the
// issuance being recorded leaves the stored bytes agreeing with the record.
//
// The defect this is written against, and the one every test here otherwise
// misses: issuing in sequence is the single case where what was read to build
// the document equals what is read to write it down, so those tests pass
// against a version and a history taken straight off the assembled document.
//
// What goes wrong without it is what a validator checks. The document claims
// a version one past what it saw, its history lists the revisions it saw, and
// the issuance it is stored against is numbered past both — so the history
// has a number missing from the middle of it and the version disagrees with
// its own last entry.
func TestAnIssuanceThatLandsWhileAnotherIsBeingBuiltIsStillNumberedRight(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", identifier})
		f.agreed(t, named)
		if _, err := f.store.Issued(t.Context(), f.who, issuer, named, "First."); err != nil {
			t.Fatalf("the first issuance: %v", err)
		}

		// A second writer, landing once, while the document for the third is
		// being assembled.
		competing := advisory.NewStore(f.db.DB)
		advisory.Between(f.store, func() {
			if _, err := competing.Issued(t.Context(), f.approver, issuer,
				named, "Landed in between."); err != nil {
				t.Fatalf("the competing issuance: %v", err)
			}
		})
		recorded, err := f.store.Issued(t.Context(), f.who, issuer, named, "Third.")
		if err != nil {
			t.Fatalf("the third issuance: %v", err)
		}
		if recorded.Ordinal != 3 {
			t.Fatalf("recorded as issuance %d, want the third", recorded.Ordinal)
		}

		var doc advisory.Document
		if err := json.Unmarshal([]byte(recorded.Document), &doc); err != nil {
			t.Fatal(err)
		}
		// One entry for the recording and one per issuance, numbered without
		// a gap, and the version is the number the history ends at.
		history := doc.Document.Tracking.RevisionHistory
		want := []string{"1", "2", "3", "4"}
		if len(history) != len(want) {
			t.Fatalf("the stored history is %+v, want an entry per revision", history)
		}
		for at := range want {
			if history[at].Number != want[at] {
				t.Errorf("entry %d is numbered %q, want %q", at, history[at].Number, want[at])
			}
		}
		if doc.Document.Tracking.Version != "4" {
			t.Errorf("the stored document is version %q, want %q",
				doc.Document.Tracking.Version, "4")
		}
	})
}

// An attempt that has to be re-run is dated when it landed, not when it first
// tried.
//
// The arm a retry reaches. Everything the closure reads it must read again:
// the moment taken before it began belongs to the attempt that was rolled
// back, so the revision that went out is dated earlier than it happened — and
// where the attempt was rolled back because somebody else took the number,
// that is a revision dated before the one it follows, in a history a
// validator compares.
//
// Driven rather than raced. Losing the race for real needs another connection
// to commit inside this transaction's window, which one of the four engines
// will not allow.
func TestAnAttemptThatIsRunAgainIsDatedWhenItLanded(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		named := f.covering(t, [2]string{"sonic", f.recorded(t, f.master)})
		f.agreed(t, named)

		handed := advisory.Ticking(f.store, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
		// What the clock had last answered when the attempt that was rolled
		// back reached the write. Recorded here rather than counted
		// afterwards, because what is being pinned is that the attempt which
		// landed read the clock again rather than keeping this.
		var rolledBack time.Time
		advisory.Stumble(f.store, func() {
			rolledBack = (*handed)[len(*handed)-1]
		})
		recorded, err := f.store.Issued(t.Context(), f.who, issuer, named, "Published.")
		if err != nil {
			t.Fatalf("issuing: %v", err)
		}
		if rolledBack.IsZero() {
			t.Fatal("no attempt was rolled back, so this pinned nothing")
		}
		last := (*handed)[len(*handed)-1]
		if recorded.IssuedAt.Equal(rolledBack) {
			t.Errorf("recorded at %s, which is the moment the rolled-back attempt held",
				recorded.IssuedAt)
		}
		if !recorded.IssuedAt.Equal(last) {
			t.Errorf("recorded at %s, want the moment the attempt that landed read, %s",
				recorded.IssuedAt, last)
		}
		// And the document that went out carries the same moment, since it
		// is dated from when it left.
		var doc advisory.Document
		if err := json.Unmarshal([]byte(recorded.Document), &doc); err != nil {
			t.Fatal(err)
		}
		if !doc.Document.Tracking.CurrentReleaseDate.Equal(last) {
			t.Errorf("the stored document is dated %s, want %s",
				doc.Document.Tracking.CurrentReleaseDate, last)
		}
	})
}

// A flaw named on an advisory after it has gone out does not move the
// document's first release, and so does not move the file.
//
// The year folder is that date's year. Left to move, a published document
// would be written under a second path and the one a reader already found
// would stay where it was, named by no list — which is also what makes "the
// set only grows" true.
func TestNamingAnOlderFlawAfterPublicationDoesNotMoveTheDocument(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		named := f.covering(t, [2]string{"sonic", f.recorded(t, f.master)})
		f.agreed(t, named)
		first, err := f.store.Issued(t.Context(), f.who, issuer, named, "Published.")
		if err != nil {
			t.Fatal(err)
		}
		var was advisory.Document
		if err := json.Unmarshal([]byte(first.Document), &was); err != nil {
			t.Fatal(err)
		}

		// A flaw this deployment knew about long before the ones it covers.
		older := f.openedLongAgo(t)
		if _, err := f.store.Add(t.Context(), f.who, named, "sonic", older); err != nil {
			t.Fatal(err)
		}
		doc, err := f.store.ForAdvisory(t.Context(), f.who, issuer, named)
		if err != nil {
			t.Fatal(err)
		}
		if !doc.Document.Tracking.InitialReleaseDate.Equal(
			was.Document.Tracking.InitialReleaseDate) {
			t.Errorf("the document now dates itself from %s, want the moment it went out, %s",
				doc.Document.Tracking.InitialReleaseDate,
				was.Document.Tracking.InitialReleaseDate)
		}
		if advisory.PathFor(doc) != advisory.PathFor(&was) {
			t.Errorf("the document moved to %q from %q",
				advisory.PathFor(doc), advisory.PathFor(&was))
		}
	})
}

// openedLongAgo records a flaw and backdates when this deployment knew about
// it, which is what a document dates itself from.
//
// Written to the row rather than recorded at a moved clock: what is being
// pinned is a document generated from flaws of different ages, and the age is
// the only part of the flaw this needs.
func (f *fixture) openedLongAgo(t *testing.T) string {
	t.Helper()
	identifier := f.recorded(t, f.master)
	if _, err := f.db.DB.NewUpdate().
		TableExpr(`"finding" AS "f"`).
		Set("opened_at = ?", time.Date(2019, 5, 1, 0, 0, 0, 0, time.UTC)).
		Where(`f.vulnerability_id = (SELECT v.id FROM "vulnerability" AS "v"
			WHERE v.identifier = ?)`, identifier).
		Exec(t.Context()); err != nil {
		t.Fatalf("backdating when the flaw was recorded: %v", err)
	}
	return identifier
}
