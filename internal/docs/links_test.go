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
	root := filepath.Join("..", "..")
	var checked, links int

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

		anchors := map[string]bool{}
		for _, m := range heading.FindAllStringSubmatch(string(text), -1) {
			anchors[anchorFor(m[1])] = true
		}
		for _, m := range internalLink.FindAllStringSubmatch(string(text), -1) {
			links++
			if !anchors[m[1]] {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s: the link #%s reaches no heading in that document", rel, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 || links == 0 {
		t.Fatalf("checked %d documents and %d links, which means this test found nothing to check",
			checked, links)
	}
	t.Logf("checked %d links across %d documents", links, checked)
}
