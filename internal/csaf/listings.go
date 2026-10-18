// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package csaf

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// The addresses and words the standard defines rather than leaves to a
// publisher: the schema a reader validates a document against, the scheme a
// feed states its subject under, the term for a feed of these documents, and
// the version of the provider description's own shape.
const (
	DocumentSchema  = "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json"
	FeedScheme      = "urn:ietf:params:rolie:category:information-type"
	FeedTerm        = "csaf"
	MetadataVersion = "2.0"
	// Version is the version of the standard every document states.
	Version = "2.0"
)

// The roles a provider claims. A provider serves the documents, the lists
// and the feed; a trusted provider also signs every document and publishes
// the key that verifies it.
const (
	Provider        = "csaf_provider"
	TrustedProvider = "csaf_trusted_provider"
)

// PublicKey is a key a provider signs with, as the provider description names
// it.
type PublicKey struct {
	Fingerprint string `json:"fingerprint"`
	URL         string `json:"url"`
}

// Listed is one document as every list naming it reads it.
type Listed struct {
	// Path is where the document sits below the address documents are
	// published at: a folder for the year and the filename the standard's
	// rule gives.
	Path string
	// Released is when this revision was released, which the list of changes
	// is ordered by, and Opened when the document was first released.
	Released time.Time
	Opened   time.Time
	Title    string
	// ID is the document's tracking identifier.
	ID string
	// Summary is what the document's newest revision says about itself.
	Summary string
}

// Stamp is a moment as every file here writes one.
//
// The same spelling the documents use, so that a date in the list of changes
// and the date inside the document it names are the same string rather than
// two renderings a reader has to decide are equal.
func Stamp(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }

// Newest is the latest moment any listed document was released, which the
// feed and the provider description date themselves from. Zero for none.
//
// Taken from the documents rather than from the clock, so that two answers
// over an unchanged set of documents are the same bytes.
func Newest(listed []Listed) time.Time {
	var newest time.Time
	for _, one := range listed {
		if one.Released.After(newest) {
			newest = one.Released
		}
	}
	return newest
}

// Index is every document's path, one per line.
//
// Ordered by path, which orders by year and then by identifier. The standard
// asks for a list rather than an order, and one an engine chose is a file that
// differs between two answers over the same documents.
func Index(listed []Listed) []byte {
	paths := make([]string, 0, len(listed))
	for _, one := range listed {
		paths = append(paths, one.Path)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil
	}
	return []byte(strings.Join(paths, "\n") + "\n")
}

// Changes is every document and when its current revision was released,
// newest first.
//
// The order is the standard's and is what makes the file useful: a reader who
// fetched yesterday reads until the dates stop being new to them. The path
// breaks a tie, because two documents released in the same moment would
// otherwise come back in either order.
//
// Each field is quoted, which the standard's own example does. Nothing in
// either field can carry a quote: a path is a year and a name the filename
// rule has already reduced to letters, digits, a plus, a hyphen and an
// underscore, and a date is a date.
func Changes(listed []Listed) []byte {
	rows := make([]Listed, len(listed))
	copy(rows, listed)
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].Released.Equal(rows[j].Released) {
			return rows[i].Released.After(rows[j].Released)
		}
		return rows[i].Path < rows[j].Path
	})
	var out strings.Builder
	for _, one := range rows {
		fmt.Fprintf(&out, "%q,%q\n", one.Path, Stamp(one.Released))
	}
	return []byte(out.String())
}

// FeedName is what a feed of documents that may travel calls itself.
//
// A token rather than the feed's own address, which would be the obvious
// unique name and is refused: the shape a reader validates a feed against
// allows letters, digits, a plus, a hyphen, an underscore and a dot, and an
// address carries a colon and two slashes.
//
// The prefix a deployment mints its advisories under goes in front of it,
// because a reader collecting feeds from several publishers holds several of
// these and the prefix is the short name this publisher is already recognized
// by. A deployment with no prefix takes the bare name.
func FeedName(prefix string) string {
	if prefix == "" {
		return "csaf-feed-tlp-white"
	}
	return strings.ToLower(prefix) + "-csaf-feed-tlp-white"
}

// Beside is a file that sits beside every document under the document's own
// name with a suffix, and what a feed entry calls it.
type Beside struct {
	Rel    string
	Suffix string
}

// FeedOf is the documents as one ROLIE feed.
//
// id is what the feed calls itself, title its title, and self its own
// address. at turns a path below the published address into an address, and
// beside is every file that sits beside each document, which the feed names
// in the document's entry.
//
// Newest first, on the moment rather than on the way it is written. The
// spelling trims trailing zeros, so a half second and fifty-one hundredths
// differ first at a digit against the letter that ends the one without it, and
// the later of the two sorts first.
func FeedOf(id, title, self string, at func(string) string, beside []Beside,
	listed []Listed) Feed {

	rows := make([]Listed, len(listed))
	copy(rows, listed)
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].Released.Equal(rows[j].Released) {
			return rows[i].Released.After(rows[j].Released)
		}
		return rows[i].ID < rows[j].ID
	})
	entries := make([]Entry, 0, len(rows))
	for _, one := range rows {
		address := at(one.Path)
		links := []Link{{Rel: "self", Href: address}}
		for _, file := range beside {
			links = append(links, Link{Rel: file.Rel, Href: at(one.Path + file.Suffix)})
		}
		entries = append(entries, Entry{
			ID: one.ID, Title: one.Title, Links: links,
			Published: Stamp(one.Opened), Updated: Stamp(one.Released),
			Summary: Summary{Content: one.Summary},
			Content: Content{Type: "application/json", Source: address},
			Format:  Format{Schema: DocumentSchema, Version: Version},
		})
	}
	return Feed{Feed: FeedBody{
		ID: id, Title: title,
		Links:      []Link{{Rel: "self", Href: self}},
		Categories: []Category{{Scheme: FeedScheme, Term: FeedTerm}},
		Updated:    Stamp(Newest(listed)),
		Entries:    entries,
	}}
}
