// Package docs holds no code. It exists so that the documents this project
// leans on are checked by the same gate the code is.
package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// heading matches a markdown heading, and internalLink a link into the same
// document.
var (
	heading      = regexp.MustCompile(`(?m)^#{1,6}\s+(.*)$`)
	internalLink = regexp.MustCompile(`\]\(#([^)]+)\)`)
	notInAnchor  = regexp.MustCompile(`[^\p{L}\p{N}\s-]`)
	// A link to another document, with the fragment it names where it has
	// one. These were invisible: internalLink requires the target to begin
	// with "#", so every link from one document to another went unchecked and
	// renaming any of them left the links dangling with the gate green.
	crossLink = regexp.MustCompile(`\]\((?:\./)?([^):#?]+\.md)(?:#([^)]*))?\)`)
	// Anchors invented inside a code fence are not headings. The sibling gate
	// strips fences before reading headings and this one did not, so a heading
	// written in an example resolved a link that reaches nothing.
	fenced = regexp.MustCompile("(?s)```.*?```")
)

// anchorFor derives the fragment a heading is reachable by.
//
// The rule is the one the forge applies when it renders these: lower-cased,
// anything that is not a letter, a number, a space or a hyphen removed, then
// spaces turned into hyphens. Punctuation being *removed* rather than replaced
// is what catches people out — a heading separated by a dash leaves two spaces
// behind it and therefore two hyphens, which nobody writing the table of
// contents by hand would think to type.
func anchorFor(text string) string {
	lowered := strings.ToLower(strings.TrimSpace(text))
	stripped := notInAnchor.ReplaceAllString(lowered, "")
	return strings.ReplaceAll(stripped, " ", "-")
}

func TestEveryLinkInsideADocumentReachesAHeading(t *testing.T) {
	// A table of contents rots silently: renaming a section leaves the link
	// pointing at nothing, and the document still renders, so nobody finds out
	// until they click it. That is how the entry for one section here came to
	// point at a name it had not carried for some time.
	//
	// Links between documents too, and their fragments. Renaming a design
	// document used to dangle every link to it with nothing failing.
	root := filepath.Join("..", "..")
	var checked, links, crossing int
	anchorsIn := map[string]map[string]bool{}
	type pointsAt struct{ from, to, fragment string }
	var across []pointsAt

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
		checked++

		body := fenced.ReplaceAllString(string(text), "")
		anchors := map[string]bool{}
		for _, m := range heading.FindAllStringSubmatch(body, -1) {
			anchors[anchorFor(m[1])] = true
		}
		anchorsIn[filepath.Clean(path)] = anchors
		rel, _ := filepath.Rel(root, path)
		for _, m := range internalLink.FindAllStringSubmatch(body, -1) {
			links++
			if !anchors[m[1]] {
				t.Errorf("%s: the link #%s reaches no heading in that document", rel, m[1])
			}
		}
		for _, m := range crossLink.FindAllStringSubmatch(body, -1) {
			if strings.Contains(m[0], "://") {
				continue
			}
			crossing++
			across = append(across, pointsAt{
				from: path, to: filepath.Join(filepath.Dir(path), m[1]), fragment: m[2],
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Resolved after the walk, so that a link may point at a document the walk
	// had not reached yet.
	for _, link := range across {
		from, _ := filepath.Rel(root, link.from)
		to, _ := filepath.Rel(root, link.to)
		anchors, read := anchorsIn[filepath.Clean(link.to)]
		if !read {
			if _, err := os.Stat(link.to); err != nil {
				t.Errorf("%s: the link to %s reaches no document", from, to)
			}
			continue
		}
		if link.fragment != "" && !anchors[link.fragment] {
			t.Errorf("%s: the link to %s#%s reaches that document and no heading in it",
				from, to, link.fragment)
		}
	}

	if checked == 0 || links == 0 || crossing == 0 {
		t.Fatalf("checked %d documents, %d links inside one and %d between two, "+
			"which means this test found nothing to check", checked, links, crossing)
	}
	t.Logf("checked %d links inside a document and %d between two, across %d documents",
		links, crossing, checked)
}
