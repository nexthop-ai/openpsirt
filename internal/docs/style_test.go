package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The design documents are written in one style, and these are the parts of it
// a machine can check.
//
// The rest is judgment and lives in AGENTS.md: statements rather than argument,
// rationale in a Limits block rather than woven through behavior, enumerations
// as tables. What is checked here is what regresses silently — a section added
// without a table-of-contents entry, and a heading that has drifted back into
// being a sentence.

var (
	designHeading = regexp.MustCompile(`(?m)^(#{2,3})\s+(.*)$`)
	// The label and the anchor, both captured. Reading the label alone would
	// compare heading text against entry text and leave the destination out
	// of it, so an entry could read as one section and navigate to another.
	contentsEntry = regexp.MustCompile(`(?m)^-\s+\[([^\]]+)\]\(#([^)]+)\)`)
	fence         = regexp.MustCompile("(?s)```.*?```")
)

// headingWords is the bound a heading may not exceed.
//
// Six is not arbitrary: it is what a noun phrase naming a mechanism takes, and
// what a sentence does not. "Incomplete upgrades" is two; "A bump that did not
// reach the fix" is eight, and the length is what makes it a teaser rather than
// a name.
const headingWords = 6

func designDocuments(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "DESIGN-*.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no design documents found")
	}
	docs := map[string]string{}
	for _, path := range paths {
		body, err := os.ReadFile(path) //nolint:gosec // this repository's own documents
		if err != nil {
			t.Fatal(err)
		}
		docs[filepath.Base(path)] = fence.ReplaceAllString(string(body), "")
	}
	return docs
}

func TestEveryDesignDocumentListsItsOwnSections(t *testing.T) {
	// A section added without an entry is a section nobody scanning the
	// contents knows exists, and the drift is silent: the document renders,
	// the links all work, and the list is simply short.
	for name, text := range designDocuments(t) {
		var headings []string
		for _, m := range designHeading.FindAllStringSubmatch(text, -1) {
			if m[1] != "##" || m[2] == "Contents" {
				continue
			}
			headings = append(headings, m[2])
		}
		var listed []string
		for _, m := range contentsEntry.FindAllStringSubmatch(text, -1) {
			listed = append(listed, m[1])
			if want := anchorFor(m[1]); m[2] != want {
				t.Errorf("%s: the Contents entry %q points at #%s, which is not the "+
					"anchor its own label derives (#%s) — it reads as one section and "+
					"navigates to another", name, m[1], m[2], want)
			}
		}
		if len(listed) == 0 {
			t.Errorf("%s: has no Contents section", name)
			continue
		}
		if strings.Join(headings, "\n") != strings.Join(listed, "\n") {
			t.Errorf("%s: Contents does not match the sections.\n  sections: %v\n  contents: %v",
				name, headings, listed)
		}
	}
}

func TestEveryDesignHeadingNamesItsSubject(t *testing.T) {
	// A heading is a noun phrase naming the mechanism, not a sentence and not
	// a teaser that withholds the subject to make somebody read on. Length is
	// the half of that a machine can judge.
	for name, text := range designDocuments(t) {
		for _, m := range designHeading.FindAllStringSubmatch(text, -1) {
			heading := strings.TrimSpace(m[2])
			if n := len(strings.Fields(heading)); n > headingWords {
				t.Errorf("%s: heading is %d words, over %d: %q",
					name, n, headingWords, heading)
			}
			if strings.HasSuffix(heading, ".") || strings.HasSuffix(heading, "?") {
				t.Errorf("%s: heading ends as a sentence: %q", name, heading)
			}
		}
	}
}
