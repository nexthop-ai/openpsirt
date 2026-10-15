// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package csaf holds the shapes of the files a CSAF provider serves to say
// what it offers and where: the provider description and the ROLIE feed.
//
// One declaration for both directions. This deployment writes them as a
// provider and reads them from a supplier, so a field spelled one way on the
// writing side and another on the reading side is a directory this
// deployment's own reader cannot follow. The field names are the standard's
// rather than ours, which is why they are spelled as it spells them.
package csaf

// Issuer is the publisher, as a document and the provider description both
// carry it.
type Issuer struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// ProviderMetadata is what a reader fetches to find out what a publisher
// offers and where.
type ProviderMetadata struct {
	CanonicalURL  string         `json:"canonical_url"`
	Distributions []Distribution `json:"distributions"`
	LastUpdated   string         `json:"last_updated"`
	Listed        bool           `json:"list_on_CSAF_aggregators"`
	Version       string         `json:"metadata_version"`
	Mirrored      bool           `json:"mirror_on_CSAF_aggregators"`
	Publisher     Issuer         `json:"publisher"`
	Role          string         `json:"role"`
}

// Distribution is one way the documents are reachable.
type Distribution struct {
	DirectoryURL string `json:"directory_url,omitempty"`
	ROLIE        *ROLIE `json:"rolie,omitempty"`
}

// ROLIE is the feeds a distribution names.
type ROLIE struct {
	Feeds []FeedDescription `json:"feeds"`
}

// FeedDescription is one feed as the provider description names it.
type FeedDescription struct {
	Summary  string `json:"summary,omitempty"`
	TLPLabel string `json:"tlp_label"`
	URL      string `json:"url"`
}

// Feed is the feed document, whose one member is the feed itself.
type Feed struct {
	Feed FeedBody `json:"feed"`
}

// FeedBody is the feed.
type FeedBody struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	Links      []Link     `json:"link"`
	Categories []Category `json:"category"`
	Updated    string     `json:"updated"`
	Entries    []Entry    `json:"entry"`
}

// Link is an address and what it is to the thing naming it.
type Link struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

// Category is a term under a scheme.
type Category struct {
	Scheme string `json:"scheme"`
	Term   string `json:"term"`
}

// Entry is one document in a feed.
type Entry struct {
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	Links     []Link  `json:"link"`
	Published string  `json:"published"`
	Updated   string  `json:"updated"`
	Summary   Summary `json:"summary"`
	Content   Content `json:"content"`
	Format    Format  `json:"format"`
}

// Summary is an entry's summary.
type Summary struct {
	Content string `json:"content"`
}

// Content is where an entry's document is.
type Content struct {
	Type   string `json:"type"`
	Source string `json:"src"`
}

// Format is the schema an entry's document meets, and its version.
type Format struct {
	Schema  string `json:"schema"`
	Version string `json:"version"`
}
