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
	// Every level, including the title, because a page's title is the first
	// heading a reader meets.
	anyHeading = regexp.MustCompile(`(?m)^(#{1,6})\s+(.*)$`)
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
	return documents(t, filepath.Join("..", "..", "DESIGN-*.md"))
}

// everyDocument is every markdown file the Spec register covers: the design
// documents, the decisions, the agent instructions, the work list, and the
// published pages.
//
// The heading rules hold for all of them. The contents rule does not — a page
// under `docs/` carries no list, because the site generates one — which is why
// the two tests take different sets.
func everyDocument(t *testing.T) map[string]string {
	t.Helper()
	docs := map[string]string{}
	for _, pattern := range []string{
		filepath.Join("..", "..", "*.md"),
		filepath.Join("..", "..", "docs", "*.md"),
	} {
		for name, text := range documents(t, pattern) {
			docs[name] = text
		}
	}
	return docs
}

func documents(t *testing.T, pattern string) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no documents matched %s, so this checked nothing", pattern)
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

func TestEveryHeadingNamesItsSubject(t *testing.T) {
	// A heading is a noun phrase naming the mechanism, not a sentence and not
	// a teaser that withholds the subject to make somebody read on. Length,
	// the wh-words and a gerund taking an object are the parts a machine can
	// judge.
	//
	// Every document rather than the design documents alone. Globbed at
	// DESIGN-*.md this never read the file that states the rule, so that file
	// carried headings of nine words while defining the bound at six.
	checked := 0
	for name, text := range everyDocument(t) {
		for _, m := range anyHeading.FindAllStringSubmatch(text, -1) {
			heading := strings.TrimSpace(m[2])
			checked++
			if n := len(strings.Fields(heading)); n > headingWords {
				t.Errorf("%s: heading is %d words, over %d: %q",
					name, n, headingWords, heading)
			}
			if strings.HasSuffix(heading, ".") || strings.HasSuffix(heading, "?") {
				t.Errorf("%s: heading ends as a sentence: %q", name, heading)
			}
			if first := strings.Fields(heading); len(first) > 0 {
				if interrogative[strings.ToLower(strings.Trim(first[0], "*`"))] {
					t.Errorf("%s: heading asks rather than names: %q", name, heading)
				}
				// A bare gerund is a noun — "Parsing", "Scanning" — and one
				// taking an object is a verb with its object: "Asking
				// upstream what is current".
				coordinated := len(first) > 1 &&
					(strings.EqualFold(first[1], "and") || strings.EqualFold(first[1], "or"))
				if len(first) > 1 && strings.HasSuffix(strings.ToLower(first[0]), "ing") &&
					!adjectival[strings.ToLower(first[0])] && !coordinated {
					t.Errorf("%s: heading is a gerund taking an object: %q", name, heading)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no headings were read, so this checked nothing")
	}
}

// interrogative are the words a heading may not open on. Each turns a name
// into a question, and a reader scanning a contents list is not asking.
var interrogative = map[string]bool{
	"what": true, "who": true, "why": true, "whether": true,
	"when": true, "where": true, "how": true, "which": true,
}

// adjectival are the gerunds that qualify the noun beside them rather than
// taking it as an object: "Routing rules", "Pending upgrades". A gerund
// followed by "and" or "or" is a coordination and needs no entry.
//
// A list rather than a rule, because English does not mark the difference and
// the alternative is refusing a correct heading. Each entry is a word somebody
// had to add deliberately, which is the point.
var adjectival = map[string]bool{
	"routing": true, "pending": true, "ranking": true, "sorting": true,
	"starting": true, "signing": true, "sending": true,
}
