package sbom

import (
	"sort"
	"strings"
)

// VocabularyOverlap reports the top-level keys more than one vocabulary
// claims, and which claim each.
//
// The dispatch reads a key by the vocabulary that owns it, before the document
// has necessarily said which format it is — a producer sorting its keys puts
// one format's contents ahead of its own version statement, so requiring the
// declaration first would refuse documents that are well formed. Two
// vocabularies claiming one key would make that routing a coin toss, which is
// a property of the tables rather than of anything a reader can check at run
// time.
//
// By vocabulary, not by format, which is the one collision first-match
// routing cannot survive: a key claimed by both SPDX tables is claimed twice
// and counted once if the question is asked per format. The reader routes a
// key to the first vocabulary holding it and keys what it has already read by
// vocabulary index, precisely because two vocabularies can be two major
// versions of one format.
func VocabularyOverlap() map[string][]string {
	claimed := map[string][]string{}
	for _, v := range vocabularies {
		for key := range v.top {
			claimed[key] = append(claimed[key], v.name)
		}
	}
	shared := map[string][]string{}
	for key, names := range claimed {
		if len(names) > 1 {
			sort.Strings(names)
			shared[key] = names
		}
	}
	return shared
}

// TopLevelKeys is every key the vocabularies claim, by vocabulary name.
//
// Exported so a test can say that each one is recorded as a path the reader
// acts on. The record is maintained by hand and four of these sat in it as
// skipped while the reader read them — an entry that says "we chose not to
// read this" is indistinguishable from one that says "we never knew it was
// there", which is what the record exists to tell apart.
func TopLevelKeys() map[string][]string {
	keys := map[string][]string{}
	for _, v := range vocabularies {
		for key := range v.top {
			keys[v.name] = append(keys[v.name], key)
		}
		sort.Strings(keys[v.name])
	}
	return keys
}

// HeaderHeld is how many structures a header-only read of this document built
// and then discarded.
//
// Exported for a test, because the reader is not reachable from outside and
// what this is about cannot be measured from the outside either: everything a
// header read holds is garbage by the time it returns, so the heap after it
// says nothing about the heap during it — and during it is inside the upload
// request.
func HeaderHeld(body string, lim Limits) (bound, contained, members int, err error) {
	c := newReader(strings.NewReader(body), lim, true)
	if err := c.read(); err != nil {
		return 0, 0, 0, err
	}
	return len(c.byRef), len(c.contained), len(c.described), nil
}
