// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package docs holds no code. It exists so that the documents this project
// leans on are checked by the same gate the code is.
package docs_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// heading matches a markdown heading, and internalLink a link into the same
// document.
var (
	heading      = regexp.MustCompile(`(?m)^#{1,6}\s+(.*)$`)
	internalLink = regexp.MustCompile(`\]\(#([^)]+)\)`)
	notInAnchor  = regexp.MustCompile(`[^\p{L}\p{N}_\s-]`)
	// What the documentation site's anchor rule removes, and the runs it
	// turns into one hyphen.
	notInSiteAnchor = regexp.MustCompile(`[^A-Za-z0-9_\s-]`)
	siteSeparators  = regexp.MustCompile(`[-\s]+`)
	// A link to anything else in the repository: a directory, the license, a
	// file of another kind. A scheme's colon rules it out; a fragment, a query
	// and a title follow the path it names.
	otherLink = regexp.MustCompile(`\]\((?:\./)?([^):#?\s]+)(?:[#?][^)\s]*)?(?:\s+"[^"]*")?\)`)
	// An inline code span, which renders no link.
	inlineCode = regexp.MustCompile("`[^`\n]*`")
	// A link to another document, with the fragment it names where it has
	// one. internalLink requires the target to begin with "#", so without
	// this every link from one document to another would go unchecked.
	crossLink = regexp.MustCompile(`\]\((?:\./)?([^):#?]+\.md)(?:#([^)]*))?\)`)
	// Anchors invented inside a code fence are not headings, so a heading
	// written in an example resolves no link.
	fenced = regexp.MustCompile("(?s)```.*?```")
)

// anchorFor derives the fragment a heading is reachable by on the forge.
//
// The rule is the one the forge applies when it renders these: lower-cased,
// anything that is not a letter, a number, an underscore, a space or a hyphen
// removed, then spaces turned into hyphens. Punctuation being *removed* rather
// than replaced is what catches people out — a heading separated by a dash
// leaves two spaces behind it and therefore two hyphens, which nobody writing
// the table of contents by hand would think to type.
func anchorFor(text string) string {
	lowered := strings.ToLower(strings.TrimSpace(text))
	stripped := notInAnchor.ReplaceAllString(lowered, "")
	return strings.ReplaceAll(stripped, " ", "-")
}

// siteAnchorFor derives the fragment a heading is reachable by on the
// documentation site, which renders docs/ with the table-of-contents
// extension's default rule: decomposed and cut to ASCII, anything that is not
// a word character, a space or a hyphen removed, lower-cased, and every run of
// spaces and hyphens turned into one hyphen. A heading separated by a dash
// takes one hyphen here and two on the forge.
func siteAnchorFor(text string) string {
	var ascii strings.Builder
	for _, r := range norm.NFKD.String(text) {
		if r < 0x80 {
			ascii.WriteRune(r)
		}
	}
	stripped := strings.ToLower(strings.TrimSpace(notInSiteAnchor.ReplaceAllString(ascii.String(), "")))
	return siteSeparators.ReplaceAllString(stripped, "-")
}

// published is whether a document is rendered by the documentation site,
// which is every page under docs/. A link is followed where its own page is
// read, so a page there is held to the site's anchors and every other
// document to the forge's.
func published(path string) bool {
	slashed := filepath.ToSlash(path)
	for strings.HasPrefix(slashed, "../") {
		slashed = strings.TrimPrefix(slashed, "../")
	}
	return strings.HasPrefix(slashed, "docs/")
}

// linkCount is how many links of each kind a check examined.
type linkCount struct{ inside, across, other int }

// linkProblems is every link in a set of documents that reaches nothing: a
// fragment naming no heading of its own document, a link to a document that is
// not there, and a fragment naming no heading of the document it reaches.
// Documents are keyed by a cleaned path; exists answers for a path that is not
// one of them.
func linkProblems(docs map[string]string, exists func(string) bool) ([]string, linkCount) {
	var problems []string
	var count linkCount
	// Each document's anchors under each rule: the forge's, and the site's.
	forgeAnchors := map[string]map[string]bool{}
	siteAnchors := map[string]map[string]bool{}
	bodies := map[string]string{}
	for path, text := range docs {
		body := fenced.ReplaceAllString(text, "")
		bodies[path] = body
		forge, site := map[string]bool{}, map[string]bool{}
		for _, m := range heading.FindAllStringSubmatch(body, -1) {
			forge[anchorFor(m[1])] = true
			site[siteAnchorFor(m[1])] = true
		}
		forgeAnchors[path], siteAnchors[path] = forge, site
	}
	for path, body := range bodies {
		anchorsIn := forgeAnchors
		if published(path) {
			anchorsIn = siteAnchors
		}
		// Headings are read from body; links from the text an inline code
		// span leaves, because a link inside one renders as text.
		links := inlineCode.ReplaceAllString(body, "")
		for _, m := range internalLink.FindAllStringSubmatch(links, -1) {
			count.inside++
			if !anchorsIn[path][m[1]] {
				problems = append(problems, fmt.Sprintf("%s: the link #%s reaches no heading in that document", path, m[1]))
			}
		}
		for _, m := range crossLink.FindAllStringSubmatch(links, -1) {
			count.across++
			to := filepath.Clean(filepath.Join(filepath.Dir(path), m[1]))
			anchors, read := anchorsIn[to]
			if !read {
				if !exists(to) {
					problems = append(problems, fmt.Sprintf("%s: the link to %s reaches no document", path, to))
				}
				continue
			}
			if m[2] != "" && !anchors[m[2]] {
				problems = append(problems, fmt.Sprintf(
					"%s: the link to %s#%s reaches that document and no heading in it", path, to, m[2]))
			}
		}
		for _, m := range otherLink.FindAllStringSubmatch(links, -1) {
			if strings.HasSuffix(m[1], ".md") {
				continue
			}
			count.other++
			to := filepath.Clean(filepath.Join(filepath.Dir(path), m[1]))
			if !exists(to) {
				problems = append(problems, fmt.Sprintf("%s: the link to %s reaches nothing", path, to))
			}
		}
	}
	sort.Strings(problems)
	return problems, count
}

func TestEveryLinkInsideADocumentReachesAHeading(t *testing.T) {
	// A table of contents rots silently: renaming a section leaves the link
	// pointing at nothing, and the document still renders, so nobody finds out
	// until they click it. Links between documents too, and their fragments,
	// so that renaming a design document cannot dangle every link to it in
	// silence.
	root := filepath.Join("..", "..")
	docs := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "bin", "target":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}
		text, err := os.ReadFile(path) //nolint:gosec // walking this repository's own documents
		if err != nil {
			return err
		}
		docs[filepath.Clean(path)] = string(text)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	problems, count := linkProblems(docs, func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	})
	for _, problem := range problems {
		t.Error(problem)
	}
	if len(docs) == 0 || count.inside == 0 || count.across == 0 || count.other == 0 {
		t.Fatalf("checked %d documents, %d links inside one, %d between two and %d to another file, "+
			"which means this test found nothing to check", len(docs), count.inside, count.across, count.other)
	}
	t.Logf("checked %d links inside a document, %d between two and %d to another file, across %d documents",
		count.inside, count.across, count.other, len(docs))
}

// Each way a link reaches nothing is reported, and a link that reaches its
// heading is not.
func TestALinkThatReachesNothingIsReported(t *testing.T) {
	docs := map[string]string{
		"a.md": "# A\n\n## Scope rules\n\n[in](#scope-rules) [there](b.md#the-end)\n",
		"b.md": "# B\n\n## The end\n",
	}
	none := func(string) bool { return false }
	if problems, _ := linkProblems(docs, none); len(problems) != 0 {
		t.Errorf("links that reach their headings were reported: %v", problems)
	}
	for what, text := range map[string]string{
		"a fragment naming no heading here":     "# A\n\n[in](#nothing)\n",
		"a heading only inside a code fence":    "# A\n\n```\n## Fenced\n```\n\n[in](#fenced)\n",
		"a document that is not there":          "# A\n\n[there](gone.md)\n",
		"a fragment naming no heading there":    "# A\n\n[there](b.md#nothing)\n",
		"a file of another kind not there":      "# A\n\n[there](gone.txt)\n",
		"a directory not there":                 "# A\n\n[there](gone/)\n",
		"a file not there, with a fragment":     "# A\n\n[there](gone.go#L3)\n",
		"a file not there, with a query":        "# A\n\n[there](gone.txt?raw=1)\n",
		"a file not there, with a title":        "# A\n\n[there](gone.txt \"t\")\n",
		"a forge anchor dropping an underscore": "# A\n\n## OPENPSIRT_ADDR\n\n[in](#openpsirtaddr)\n",
	} {
		problems, _ := linkProblems(map[string]string{"a.md": text, "b.md": docs["b.md"]}, none)
		if len(problems) == 0 {
			t.Errorf("%s was not reported", what)
		}
	}
}

// A page under docs/ is held to the site's anchors and every other document to
// the forge's, each in both directions.
func TestEachDocumentIsHeldToTheAnchorsWhereItIsRead(t *testing.T) {
	heading := "# A\n\n## Upgrades — from v0.1\n\n## OPENPSIRT_ADDR\n\n## Café\n\n"
	none := func(string) bool { return false }
	for _, c := range []struct {
		what, path, link string
		reported         bool
	}{
		{"the forge's dash on the forge", "a.md", "#upgrades--from-v01", false},
		{"the site's dash on the forge", "a.md", "#upgrades-from-v01", true},
		{"the site's dash on the site", "docs/a.md", "#upgrades-from-v01", false},
		{"the forge's dash on the site", "docs/a.md", "#upgrades--from-v01", true},
		{"an underscore on the forge", "a.md", "#openpsirt_addr", false},
		{"an underscore on the site", "docs/a.md", "#openpsirt_addr", false},
		{"an accented letter on the forge", "a.md", "#café", false},
		{"an accented letter on the site", "docs/a.md", "#cafe", false},
		{"an accented letter kept on the site", "docs/a.md", "#café", true},
	} {
		problems, _ := linkProblems(map[string]string{c.path: heading + "[in](" + c.link + ")\n"}, none)
		if got := len(problems) > 0; got != c.reported {
			t.Errorf("%s: reported = %v, want %v (%v)", c.what, got, c.reported, problems)
		}
	}
}

// A link to a file of another kind that is there, or one written inside an
// inline code span, is not reported.
func TestALinkToAnotherFileThatIsThereIsNotReported(t *testing.T) {
	there := func(path string) bool { return path == "LICENSE" || path == "docs" }
	text := "# A\n\n[license](LICENSE) [site](docs/) `[x](gone.txt)` `[y](#nowhere)` `[z](gone.md)`\n"
	if problems, count := linkProblems(map[string]string{"a.md": text}, there); len(problems) != 0 || count.other != 2 {
		t.Errorf("links that reach their files: %v, counted %d, want none and 2", problems, count.other)
	}
}
