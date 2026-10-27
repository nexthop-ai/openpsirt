// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package docs_test

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

var (
	// A design document named by path.
	designReference = regexp.MustCompile(`design-docs/([a-z0-9-]+)\.md`)
	// The section mark that may follow one. The heading is the text after it,
	// matched by prefix, because nothing marks where a heading written in
	// prose ends; the text is read from the mark onward rather than matched,
	// so a second reference on the same line is found by its own match.
	sectionMark = regexp.MustCompile("^`?\\]?(?:[ \t]*(?:\n[ \t]*(?://+|#+|\\*|--|;+)?[ \t]*)?)§[ \t]*")
	// A comment's marker at the start of a continued line, removed so a
	// heading wrapped across two comment lines reads as one.
	continuation = regexp.MustCompile(`\n[ \t]*(?://+|#+|\*|--|;+)?[ \t]*`)
	// A row in the design index: the document its link names.
	indexRow = regexp.MustCompile(`(?m)^\|\s*\[[^\]]+\]\(design-docs/([a-z0-9-]+\.md)\)`)
)

// referenced files are the kinds a reference to a design document is written
// in: code and its comments, configuration, and prose.
var referenced = []string{".go", ".ts", ".tsx", ".mjs", ".js", ".md", ".yml", ".yaml", ".mk", ".txt", ".sql", ".py", ".tpl"}

// referenceProblems reports each reference to a design document that names no
// file, and each section reference that begins with no heading in its file.
// headings maps a document's name to its headings; a document missing from it
// is not there.
func referenceProblems(files map[string]string, headings map[string][]string) (problems []string, count int) {
	for name, body := range files {
		for _, m := range designReference.FindAllStringSubmatchIndex(body, -1) {
			count++
			doc := body[m[2]:m[3]] + ".md"
			line := strings.Count(body[:m[0]], "\n") + 1
			held, there := headings[doc]
			if !there {
				problems = append(problems, fmt.Sprintf("%s:%d: design-docs/%s is not there", name, line, doc))
				continue
			}
			mark := sectionMark.FindStringIndex(body[m[1]:])
			if mark == nil {
				continue
			}
			// The section text, with the lines after it joined on, so a
			// heading wrapped onto the next line is still read whole.
			from := m[1] + mark[1]
			end := min(len(body), from+200)
			text := strings.Join(strings.Fields(continuation.ReplaceAllString(body[from:end], " ")), " ")
			if !slices.ContainsFunc(held, func(h string) bool { return beginsWith(text, h) }) {
				problems = append(problems, fmt.Sprintf("%s:%d: design-docs/%s has no heading beginning %q",
					name, line, doc, firstWords(text, 6)))
			}
		}
	}
	sort.Strings(problems)
	return problems, count
}

// beginsWith reports whether text starts with heading as whole words.
func beginsWith(text, heading string) bool {
	if !strings.HasPrefix(text, heading) {
		return false
	}
	rest := text[len(heading):]
	return rest == "" || !strings.ContainsAny(rest[:1], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}

func firstWords(text string, n int) string {
	words := strings.Fields(text)
	return strings.Join(words[:min(n, len(words))], " ")
}

// designHeadings reads every design document's headings, keyed by file name.
func designHeadings(t *testing.T) map[string][]string {
	t.Helper()
	held := map[string][]string{}
	for name, text := range designDocuments(t) {
		for _, m := range anyHeading.FindAllStringSubmatch(fence.ReplaceAllString(text, ""), -1) {
			held[filepath.Base(name)] = append(held[filepath.Base(name)], strings.TrimSpace(m[2]))
		}
	}
	return held
}

func TestEveryReferenceToADesignSectionReachesAHeading(t *testing.T) {
	// A section reference in a code comment is how somebody reading the code
	// finds the rule it follows, and renaming or splitting a document dangles
	// it silently: nothing renders it as a link.
	headings := designHeadings(t)
	t.Chdir(filepath.Join("..", ".."))
	files := map[string]string{}
	if _, err := walk.Paths(nil, func(name string) (bool, error) {
		if !slices.Contains(referenced, path.Ext(name)) && path.Base(name) != "Makefile" {
			return false, nil
		}
		body, err := os.ReadFile(name) //nolint:gosec // walking this repository's own files
		if err != nil {
			return false, err
		}
		files[name] = string(body)
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	problems, count := referenceProblems(files, headings)
	if count == 0 {
		t.Fatal("no reference to a design document was found, so this checked nothing")
	}
	for _, problem := range problems {
		t.Error(problem)
	}
	t.Logf("checked %d references to design documents across %d files", count, len(files))
}

// dd is the folder's path written apart from the names in these fixtures, so
// the walk over this file does not read the fixtures as references.
const dd = "design-docs/"

// A reference to a heading that is there, wrapped or followed by punctuation,
// is not reported; one to a missing file or heading is.
func TestAReferenceThatReachesNothingIsReported(t *testing.T) {
	headings := map[string][]string{"a.md": {"Reads a write depends on", "Limits"}}
	for what, body := range map[string]string{
		"a file alone":           "see " + dd + "a.md.",
		"a heading in backticks": "(`" + dd + "a.md` § Reads a write depends on). More",
		"a heading wrapped":      "// (`" + dd + "a.md` § Reads a\n// write depends on). The",
		"a section mark wrapped": "(`" + dd + "a.md`\n§ Limits holds it)",
		"a link around it":       "[" + dd + "a.md § Limits](" + dd + "a.md#limits)",
	} {
		if problems, _ := referenceProblems(map[string]string{"x.go": body}, headings); len(problems) != 0 {
			t.Errorf("%s was reported: %v", what, problems)
		}
	}
	for what, body := range map[string]string{
		"a file not there":          "see " + dd + "gone.md",
		"a heading not there":       dd + "a.md § Writes",
		"a heading cut short":       dd + "a.md § Reads a write",
		"a heading run into a word": dd + "a.md § Limitsless",
		"a section mark wrapped":    "`" + dd + "a.md`\n// § Writes",
		"a second on the same line": dd + "a.md § Limits, and " + dd + "a.md § Writes",
	} {
		if problems, _ := referenceProblems(map[string]string{"x.go": body}, headings); len(problems) == 0 {
			t.Errorf("%s was not reported", what)
		}
	}
}

// indexProblems reports each design document the index has no row for, and
// each row naming a document that is not there.
func indexProblems(index string, documents []string) []string {
	var problems []string
	rows := map[string]bool{}
	for _, m := range indexRow.FindAllStringSubmatch(index, -1) {
		rows[m[1]] = true
		if !slices.Contains(documents, m[1]) {
			problems = append(problems, fmt.Sprintf("DESIGN.md has a row for design-docs/%s, which is not there", m[1]))
		}
	}
	for _, doc := range documents {
		if !rows[doc] {
			problems = append(problems, fmt.Sprintf(dd+"%s has no row in DESIGN.md, so nobody reading the index finds it", doc))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestEveryDesignDocumentHasAnIndexRow(t *testing.T) {
	index, err := os.ReadFile(filepath.Join("..", "..", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	var documents []string
	for name := range designDocuments(t) {
		documents = append(documents, filepath.Base(name))
	}
	if len(indexRow.FindAllString(string(index), -1)) == 0 {
		t.Fatal("DESIGN.md has no rows, so this checked nothing")
	}
	for _, problem := range indexProblems(string(index), documents) {
		t.Error(problem)
	}
}

// A document with no row and a row with no document are both reported.
func TestIndexProblemsReportsEachDirection(t *testing.T) {
	index := "| Document | Covers |\n|---|---|\n| [a](" + dd + "a.md) | A |\n| [gone](" + dd + "gone.md) | G |\n"
	got := indexProblems(index, []string{"a.md", "b.md"})
	if len(got) != 2 || !strings.Contains(got[0], "gone.md") || !strings.Contains(got[1], "b.md") {
		t.Errorf("problems: %v, want gone.md's row and b.md's missing row", got)
	}
	if got := indexProblems(index, []string{"a.md", "gone.md"}); len(got) != 0 {
		t.Errorf("a matching index was reported: %v", got)
	}
}
