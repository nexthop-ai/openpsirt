package sbom

import (
	"fmt"
	"io"
	"strings"
)

// vocabulary is one format's reading of a document's top-level keys.
//
// Each owns a set of keys and nothing else knows them. Adding a format is a
// table and the handlers it names.
type vocabulary struct {
	format Format
	// name is what a refusal calls it, which is narrower than the format:
	// telling somebody their file states both SPDX and SPDX would say nothing.
	name string
	top  map[string]func(*reader) error
}

// vocabularies are the formats read, in the order a document is tried against.
//
// Three of them for two formats: the third major version of SPDX has a table
// of its own rather than a branch in the second's, because it shares no key
// with it. A vocabulary rather than a format is what a document is checked
// against being two of, since two major versions of one format are as
// unreadable together as two formats are.
var vocabularies = []vocabulary{
	{format: CycloneDX, name: "CycloneDX 1.x", top: cyclonedxTop},
	{format: SPDX, name: "SPDX 2.x", top: spdxTop},
	{format: SPDX, name: "SPDX 3.x", top: spdx3Top},
}

// ReadHeader reads what a document says about itself and stops.
//
// The contents are skipped rather than parsed where the format states its
// header outside them, which two of the three do. It is not free even then —
// the interesting fields are not guaranteed to come first, and some producers
// sort their keys — but skipping values costs a walk rather than a structure
// per component.
//
// The third states its header inside the contents, as one entry of the array
// its packages are in, so that one is walked in full and builds nothing from
// what it walks. The bounds hold on this pass either way, because what they
// stop is the walk.
//
// None of them answers which component the document is about, where
// the format states that by pointing at one of the contents. Nothing asks: the
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
// A key is read by the format that owns it rather than by the format the
// document has declared so far, because the declaration arrives in no
// guaranteed position: a producer sorting its keys puts SPDX's `packages`
// ahead of its `spdxVersion`, and CycloneDX's `components` ahead of nothing at
// all. Requiring the declaration first would refuse documents that are
// perfectly well formed.
//
// The vocabulary each key was routed to is recorded, and that rather than
// the keys being disjoint is what makes the arrangement safe. A handler writes
// to the document before anything has checked what the document is, and both
// formats state an identity — so a file carrying both keys would be stored
// under whichever came last, which is a different identity for the same bytes
// depending only on how its producer sorted them.
func (c *reader) read() error {
	err := c.b.object(func(key string) error {
		for at, v := range vocabularies {
			handler, ours := v.top[key]
			if !ours {
				continue
			}
			c.fired[at] = true
			return handler(c)
		}
		return c.b.skip()
	})
	if err != nil {
		return fmt.Errorf("reading scan file: %w", err)
	}
	if err := c.checkFormat(); err != nil {
		return err
	}
	// One format states its build time inside the contents, pointing at it
	// rather than carrying it, so it cannot be settled where it is read — and
	// nor can a fault in it be reported where the other two report theirs.
	c.spdx3Settle()
	if c.settleErr != nil {
		return fmt.Errorf("reading scan file: %w", c.settleErr)
	}
	return nil
}

// checkFormat refuses a document that did not say what it is, said it was two
// things, or said only half of what one of them is.
//
// It does not check that the document named a component of its own. No
// format requires one, and the scan was filed against something that says what
// it is about.
func (c *reader) checkFormat() error {
	if len(c.fired) > 1 {
		// Keys from two formats were read, so this is not either of them, and
		// whichever handler ran last has already written over the other's
		// answer. Refused rather than preferred: nothing here can say which
		// half the producer meant.
		var named []string
		for at, v := range vocabularies {
			if c.fired[at] {
				named = append(named, v.name)
			}
		}
		return fmt.Errorf("scan file states both %s, so which format it is cannot be settled",
			strings.Join(named, " and "))
	}
	if c.declared == "" {
		return fmt.Errorf("scan file does not say what format it is: it is neither %s nor %s",
			CycloneDX, SPDX)
	}
	// Half a declaration is not a declaration. Either key alone leaves the
	// other unstated, and an unstated version is a version this was not written
	// against — which is what the by-name refusal exists to catch. Stating one
	// of the two is the shape a fragment has, or of something else entirely
	// whose keys happen to look familiar.
	if c.declared == CycloneDX && (!c.named || !c.versioned) {
		missing := "specVersion"
		if !c.named {
			missing = "bomFormat"
		}
		return fmt.Errorf("scan file states only half of what %s is: %s is missing",
			CycloneDX, missing)
	}
	c.doc.Format = c.declared
	return nil
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
