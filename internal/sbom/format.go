package sbom

import (
	"fmt"
	"io"
	"strings"
)

// vocabularies are the formats read, in the order a document is tried against.
//
// Each one owns a set of top-level keys and nothing else knows them. Adding a
// format is a table and the handlers it names.
var vocabularies = []map[string]func(*reader) error{cyclonedxTop, spdxTop}

// ReadHeader reads what a document says about itself and stops.
//
// The contents are skipped rather than parsed, so this stays cheap on a file
// that is about to be refused. It is not free — the interesting fields are not
// guaranteed to come first, and some producers sort their keys — but skipping
// values costs a walk rather than a structure per component.
//
// What it does not answer is which component the document is about, where the
// format states that by pointing at one of the contents. Nothing asks: the
// arrival decision turns on the document's identity and its build time, and
// the root is settled by the read that applies the scan.
func ReadHeader(r io.Reader, lim Limits) (Header, error) {
	c := newReader(r, lim, true)
	if err := c.read(); err != nil {
		return Header{}, err
	}
	return c.doc.Header, nil
}

// Read reads a whole document.
//
// Nothing partial is returned. A half-read inventory is indistinguishable from
// a product that shrank, and acting on one would close findings that are still
// somebody's problem.
func Read(r io.Reader, lim Limits) (*Document, error) {
	c := newReader(r, lim, false)
	if err := c.read(); err != nil {
		return nil, err
	}
	return c.finish()
}

// read walks the document once, routing each top-level key to the vocabulary
// that owns it.
//
// **A key is read by the format that owns it rather than by the format the
// document has declared so far**, because the declaration arrives in no
// guaranteed position: a producer sorting its keys puts SPDX's `packages`
// ahead of its `spdxVersion`, and CycloneDX's `components` ahead of nothing at
// all. Requiring the declaration first would refuse documents that are
// perfectly well formed.
//
// What makes that safe is that the vocabularies claim no key in common, which
// a test asserts rather than a reader assuming. A document is still refused
// for declaring no format, and for declaring one this was not written
// against — the first at the end of the walk, the second where it is read.
func (c *reader) read() error {
	err := c.b.object(func(key string) error {
		for _, vocabulary := range vocabularies {
			if handler, ours := vocabulary[key]; ours {
				return handler(c)
			}
		}
		return c.b.skip()
	})
	if err != nil {
		return fmt.Errorf("reading scan file: %w", err)
	}
	return c.checkFormat()
}

// checkFormat refuses a document that never said what it was.
//
// A file carrying components and naming no format is the case this catches: a
// fragment, a hand-edited document, or something of another format entirely
// whose keys happen to look familiar. Guessing from the contents is what the
// declaration exists to make unnecessary.
//
// What it does not check is that the document named a component of its own.
// Neither format requires one, and the scan was filed against something that
// says what it is about.
func (c *reader) checkFormat() error {
	if c.declared != "" {
		return nil
	}
	return fmt.Errorf("scan file does not say what format it is: it is neither %s nor %s",
		cyclonedxName, spdxName)
}

// sentinel reports the value of a field, reading a format's own words for
// "nothing to say here" as nothing.
//
// SPDX requires several fields to be present and offers NOASSERTION and NONE
// for a producer that has no value for one. Taken literally, a package would
// carry the version "NOASSERTION", which is a string a scanner would try to
// match and a person would read as a version. They mean absent, so they are
// absent.
func sentinel(value string) string {
	switch strings.TrimSpace(value) {
	case "NOASSERTION", "NONE":
		return ""
	}
	return value
}
