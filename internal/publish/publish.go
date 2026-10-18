// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package publish keeps the security documents this deployment serves to
// anybody: a CSAF VEX document for each issue in each product whose documents
// are published, and an OpenVEX document for each of its branches and tags.
//
// A published revision is a fact about a moment. What a reader was told, and
// when, cannot be worked out again once a decision moves or a scan lands, and
// a document's revision history and its version are what a reader's tooling
// tells one revision from the next by. So a revision is written when what the
// document states moves, and the bytes written are the bytes served until it
// moves again.
//
// Read only through a subject. The pass that writes reads the findings as
// anybody at all would, so nothing undisclosed and nothing about a product
// that is not published reaches a document; the surface that serves them
// reads the documents the same way, so a document written before a product
// stopped publishing is not served after.
package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/uptrace/bun"
)

// The two kinds of document kept here.
const (
	// CSAFVEX is a CSAF document of the VEX profile about one issue in one
	// product, across every branch, tag and variant of it.
	CSAFVEX = "csaf-vex"
	// OpenVEX is an OpenVEX document about one branch or tag of one
	// product, across its variants, at what each last scanned.
	OpenVEX = "openvex"
)

// The paths documents are served at, below the address the deployment is
// reached at. The CSAF ones are the standard's: the provider description at
// the well-known address, and the documents that may travel in a folder of
// their own below it.
const (
	// WellKnown is the folder the standard reserves for a provider.
	WellKnown = "/.well-known/csaf/"
	// MetadataPath is the provider description.
	MetadataPath = WellKnown + "provider-metadata.json"
	// DirectoryPath is the folder of documents that may travel, with a folder
	// per year below it and the lists beside them.
	DirectoryPath = WellKnown + "white/"
	IndexPath     = DirectoryPath + "index.txt"
	ChangesPath   = DirectoryPath + "changes.csv"
	FeedPath      = DirectoryPath + "csaf-feed-tlp-white.json"
	// KeysPath is the folder the public key is served in, under its
	// fingerprint.
	KeysPath = WellKnown + "openpgp/"
	// OpenVEXPath is the folder of OpenVEX documents, a folder per product,
	// and OpenVEXIndex the list of them.
	OpenVEXPath  = "/openvex/"
	OpenVEXIndex = OpenVEXPath + "index.txt"
)

// The files served beside every document, under the document's own name.
const (
	SHA256Suffix    = ".sha256"
	SHA512Suffix    = ".sha512"
	SignatureSuffix = ".asc"
)

// Document is one published document, holding the revision a reader is handed
// now.
type Document struct {
	bun.BaseModel `bun:"table:published_document,alias:pub"`

	ID        int64  `bun:"id,pk,autoincrement"`
	ProductID int64  `bun:"product_id,notnull"`
	Kind      string `bun:"kind,notnull"`
	// Subject is what the document is about within the product: the issue's
	// name, or the branch or tag's.
	Subject string `bun:"subject,notnull"`
	// Path is where it is served, and PathDigest what a request is matched on.
	Path       string `bun:"path,notnull"`
	PathDigest string `bun:"path_digest,notnull"`
	TrackingID string `bun:"tracking_id,notnull"`
	Title      string `bun:"title,notnull"`
	Version    int    `bun:"version,notnull"`
	// FirstAt is when its first revision was released and CurrentAt when this
	// one was.
	FirstAt   time.Time `bun:"first_at,notnull"`
	CurrentAt time.Time `bun:"current_at,notnull"`
	// Statuses is the statuses the deployment published when this revision
	// was written.
	Statuses string `bun:"statuses,notnull"`
	// Settled is a digest of what the document states, with its dates, its
	// version and its history left out.
	Settled     string     `bun:"settled,notnull"`
	WithdrawnAt *time.Time `bun:"withdrawn_at"`
	Body        string     `bun:"document,notnull"`
}

// digestOf is a path as a request is matched on it.
func digestOf(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}

// settled is a digest of what a document states.
func settled(stated []byte) string {
	sum := sha256.Sum256(stated)
	return hex.EncodeToString(sum[:])
}
