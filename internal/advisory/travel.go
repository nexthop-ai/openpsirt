// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"encoding/json"
	"fmt"

	"github.com/nexthop-ai/openpsirt/internal/csaf"
)

// Travelable is the one label a document served to anybody carries.
//
// The standard puts anything above it under a different path, behind an
// authentication this deployment does not do: a document nobody outside has
// been told about must not be reachable, and a document served without a
// credential cannot be one of those. The labels are the standard's four, which
// is why it is WHITE rather than the word the protocol renamed it to.
const Travelable = "WHITE"

// Travels is one advisory's document that may be served to anybody, as every
// list naming it reads it.
type Travels struct {
	// Body is the bytes as they went out, and is what a digest is taken
	// over. The document is re-read from them rather than re-marshaled from
	// what was parsed: what a reader fetches and what the digest answers for
	// have to be one string of bytes.
	Body []byte
	// Listed is the document as the lists naming it read it: where it sits,
	// when this revision and the first were released, its title, its
	// identifier, and what its newest revision says about itself.
	csaf.Listed
}

// Travelling is the newest document of each advisory that may be served to
// anybody, how many advisories were held back, and why each document that
// could not be read back could not.
//
// A document that cannot be read leaves its advisory out, and nothing older is
// carried in its place. Every revision has the same path, so carrying the one
// before would put it over a revision that may already have gone out, and put
// the lists back to that revision's release date.
//
// Walked per advisory rather than taking the newest of each outright. Whether
// a document may be served is a property of the bytes, and an advisory whose
// newest revision went to a coordinating body under embargo has a revision
// before it that is already public — so that one keeps being served rather
// than the advisory dropping out of every list it is in.
//
// sent is what has gone out, newest issuance first within each advisory, as
// Sent reads it.
func Travelling(sent []Sent) (out []Travels, held int, unread []error) {
	seen := map[string]bool{}
	// Counted per advisory rather than per revision walked past. An advisory
	// with two revisions that may not travel over one that may is served, so
	// counting the revisions reports two missing where none is.
	walked := map[string]bool{}
	for _, one := range sent {
		if seen[one.Advisory] {
			continue
		}
		walked[one.Advisory] = true
		var doc Document
		if err := json.Unmarshal([]byte(one.Document), &doc); err != nil {
			unread = append(unread, fmt.Errorf(
				"read what %s issuance %d published: %w", one.Advisory, one.Ordinal, err))
			seen[one.Advisory] = true
			continue
		}
		if !mayTravel(&doc) {
			continue
		}
		seen[one.Advisory] = true
		out = append(out, Travels{Body: []byte(one.Document), Listed: csaf.Listed{
			Path:     PathFor(&doc),
			Released: doc.Document.Tracking.CurrentReleaseDate,
			Opened:   doc.Document.Tracking.InitialReleaseDate,
			Title:    doc.Document.Title,
			ID:       doc.Document.Tracking.ID,
			Summary:  newestRevision(&doc),
		}})
	}
	for name := range walked {
		if !seen[name] {
			held++
		}
	}
	return out, held, unread
}

// mayTravel reports whether these bytes may be served to anybody.
//
// Asked of the label the document carries rather than of the record it came
// from. The record moves and the bytes do not, and what a reader is handed is
// the bytes — so a document that said it may be passed on says so for ever,
// and one that says nothing at all is not read as permission.
func mayTravel(doc *Document) bool {
	at := doc.Document.Distribution
	return at != nil && at.TLP != nil && at.TLP.Label == Travelable
}

// newestRevision is what the document's last revision entry says about itself.
func newestRevision(doc *Document) string {
	history := doc.Document.Tracking.RevisionHistory
	if len(history) == 0 {
		return ""
	}
	return history[len(history)-1].Summary
}
