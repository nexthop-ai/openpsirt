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
)

// heading matches a markdown heading, and internalLink a link into the same
// document.
var (
	heading      = regexp.MustCompile(`(?m)^#{1,6}\s+(.*)$`)
	internalLink = regexp.MustCompile(`\]\(#([^)]+)\)`)
	notInAnchor  = regexp.MustCompile(`[^\p{L}\p{N}\s-]`)
	// A link to another document, with the fragment it names where it has
	// one. internalLink requires the target to begin with "#", so without
	// this every link from one document to another would go unchecked.
	crossLink = regexp.MustCompile(`\]\((?:\./)?([^):#?]+\.md)(?:#([^)]*))?\)`)
	// Anchors invented inside a code fence are not headings, so a heading
	// written in an example resolves no link.
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

// linkCount is how many links of each kind a check examined.
type linkCount struct{ inside, across int }

// linkProblems is every link in a set of documents that reaches nothing: a
// fragment naming no heading of its own document, a link to a document that is
// not there, and a fragment naming no heading of the document it reaches.
// Documents are keyed by a cleaned path; exists answers for a path that is not
// one of them.
func linkProblems(docs map[string]string, exists func(string) bool) ([]string, linkCount) {
	var problems []string
	var count linkCount
	anchorsIn := map[string]map[string]bool{}
	bodies := map[string]string{}
	for path, text := range docs {
		body := fenced.ReplaceAllString(text, "")
		bodies[path] = body
		anchors := map[string]bool{}
		for _, m := range heading.FindAllStringSubmatch(body, -1) {
			anchors[anchorFor(m[1])] = true
		}
		anchorsIn[path] = anchors
	}
	for path, body := range bodies {
		for _, m := range internalLink.FindAllStringSubmatch(body, -1) {
			count.inside++
			if !anchorsIn[path][m[1]] {
				problems = append(problems, fmt.Sprintf("%s: the link #%s reaches no heading in that document", path, m[1]))
			}
		}
		for _, m := range crossLink.FindAllStringSubmatch(body, -1) {
			if strings.Contains(m[0], "://") {
				continue
			}
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
	if len(docs) == 0 || count.inside == 0 || count.across == 0 {
		t.Fatalf("checked %d documents, %d links inside one and %d between two, "+
			"which means this test found nothing to check", len(docs), count.inside, count.across)
	}
	t.Logf("checked %d links inside a document and %d between two, across %d documents",
		count.inside, count.across, len(docs))
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
		"a fragment naming no heading here":  "# A\n\n[in](#nothing)\n",
		"a heading only inside a code fence": "# A\n\n```\n## Fenced\n```\n\n[in](#fenced)\n",
		"a document that is not there":       "# A\n\n[there](gone.md)\n",
		"a fragment naming no heading there": "# A\n\n[there](b.md#nothing)\n",
	} {
		problems, _ := linkProblems(map[string]string{"a.md": text, "b.md": docs["b.md"]}, none)
		if len(problems) == 0 {
			t.Errorf("%s was not reported", what)
		}
	}
}
