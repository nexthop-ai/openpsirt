// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package build holds no code. It exists so that the makefiles this project
// is built by are checked by the gate they run, the way internal/docs checks
// the documents.
package build_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A target at the start of a line, and the names one .PHONY declaration
// carries.
//
// The colon is required not to be an assignment: "GO := go" is a variable and
// "build:" is a target, and the two differ by the character after the colon. A
// target whose name is a variable reference is not matched, because it names a
// file rather than an action and .PHONY would be wrong about it.
var (
	target  = regexp.MustCompile(`(?m)^([A-Za-z0-9][A-Za-z0-9._-]*)[ \t]*:(?:[^=]|$)`)
	phonies = regexp.MustCompile(`(?m)^\.PHONY:(.*)$`)
)

// declarations returns what a makefile declares phony and what it defines as a
// target, both as sets.
func declarations(text string) (phony, targets map[string]bool) {
	phony, targets = map[string]bool{}, map[string]bool{}
	for _, line := range phonies.FindAllStringSubmatch(text, -1) {
		for _, name := range strings.Fields(line[1]) {
			phony[name] = true
		}
	}
	for _, match := range target.FindAllStringSubmatch(text, -1) {
		targets[match[1]] = true
	}
	return phony, targets
}

// missing returns the names in one set and not the other, sorted so a failure
// reads the same twice.
func missing(from, in map[string]bool) []string {
	var names []string
	for name := range from {
		if !in[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// An include line, which names the files make reads beside the makefile. The
// optional form, "-include", is a machine's own settings and is not matched.
var includes = regexp.MustCompile(`(?m)^include[ \t]+(.+)$`)

// makefiles is every makefile of this repository, as a path from the package:
// the makefile itself and each file its include lines name.
func makefiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	main := filepath.Join(root, "Makefile")
	body, err := os.ReadFile(main) //nolint:gosec // this repository's own makefile
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{main}
	for _, line := range includes.FindAllStringSubmatch(string(body), -1) {
		for _, name := range strings.Fields(line[1]) {
			paths = append(paths, filepath.Join(root, filepath.FromSlash(name)))
		}
	}
	return paths
}

// makefileText is every makefile of this repository, read and joined in the
// order make reads them.
func makefileText(t *testing.T) string {
	t.Helper()
	var all strings.Builder
	for _, path := range makefiles(t) {
		body, err := os.ReadFile(path) //nolint:gosec // this repository's own makefiles
		if err != nil {
			t.Fatal(err)
		}
		all.Write(body)
		all.WriteString("\n")
	}
	return all.String()
}

// Every makefile in the tree is one the makefile includes.
//
// The build is split across files make reads through include lines, so a file
// beside them that no line names is targets nobody can run and that every
// check reading the makefiles skips.
func TestEveryMakefileInTheTreeIsIncluded(t *testing.T) {
	root := filepath.Join("..", "..")
	found, err := filepath.Glob(filepath.Join(root, "Makefile*"))
	if err != nil {
		t.Fatal(err)
	}
	pieces, err := filepath.Glob(filepath.Join(root, "mk", "*.mk"))
	if err != nil {
		t.Fatal(err)
	}
	found = append(found, pieces...)
	if len(pieces) == 0 {
		t.Fatal("no makefile was found under mk, so this checked nothing")
	}
	read := map[string]bool{}
	for _, path := range makefiles(t) {
		read[filepath.Clean(path)] = true
	}
	for _, path := range found {
		if !read[filepath.Clean(path)] {
			t.Errorf("%s is a makefile the makefile does not include", filepath.ToSlash(path))
		}
	}
}

// Every target is declared phony and every declaration names a target.
//
// The convention is the whole list, not most of it, and it drifts in both
// directions: a declaration outlives the target it named, and a target added
// beside its siblings is not added to the list above them. Neither is visible
// until a file of that name exists in the checkout, and then the target
// reports "up to date" and runs nothing.
//
// Each makefile declares its own targets, so the list a target belongs on is
// in the file a reader has open.
func TestEveryTargetIsDeclaredPhonyAndEveryDeclarationNamesOne(t *testing.T) {
	paths := makefiles(t)
	examined := 0
	for _, path := range paths {
		body, err := os.ReadFile(path) //nolint:gosec // this repository's own makefiles
		if err != nil {
			t.Fatal(err)
		}
		phony, targets := declarations(string(body))
		if len(targets) == 0 {
			t.Fatalf("%s defines no targets, so this checked nothing", filepath.ToSlash(path))
		}
		examined += len(targets)
		if names := missing(targets, phony); len(names) > 0 {
			t.Errorf("%s defines %v and does not declare them phony", filepath.ToSlash(path), names)
		}
		if names := missing(phony, targets); len(names) > 0 {
			t.Errorf("%s declares %v phony and defines no such target", filepath.ToSlash(path), names)
		}
	}
	t.Logf("%d targets across %d makefiles", examined, len(paths))
}

// The join's report, asked of text holding one of each drift and of text
// holding neither.
func TestDriftIsReportedInBothDirectionsAndAgreementIsNot(t *testing.T) {
	const drifted = `.PHONY: build gone
GO := go
build:
	$(GO) build ./...
undeclared:
	$(GO) vet ./...
`
	phony, targets := declarations(drifted)
	if got := missing(targets, phony); len(got) != 1 || got[0] != "undeclared" {
		t.Errorf("a target nothing declares was reported as %v", got)
	}
	if got := missing(phony, targets); len(got) != 1 || got[0] != "gone" {
		t.Errorf("a declaration naming no target was reported as %v", got)
	}

	const agreeing = `.PHONY: build
GO := go
build:
	$(GO) build ./...
`
	phony, targets = declarations(agreeing)
	if got := missing(targets, phony); len(got) != 0 {
		t.Errorf("a declared target was reported as undeclared: %v", got)
	}
	if got := missing(phony, targets); len(got) != 0 {
		t.Errorf("a target that exists was reported as missing: %v", got)
	}
	if len(targets) != 1 {
		t.Errorf("the variable assignment was read as a target: %v", targets)
	}
}

// A test reading a document of this repository, by a relative path that climbs
// out of its package: "../../docs/x.md", or the same path in pieces with any
// directories between.
var readsADocument = regexp.MustCompile(`(?:"\.\."\s*,\s*)+(?:"[^"\n]+"\s*,\s*)*"[^"\n]+\.md"|"(?:\.\./)+[^"\n]+\.md"`)

// A test that walks out of its package and keeps the files named ".md", which
// reads every document without naming one.
var (
	climbs     = regexp.MustCompile(`"\.\."\s*,|"\.\./`)
	walksForMd = regexp.MustCompile(`"\.md"`)
)

// documentReaders is each package directory, as make names it, holding a test
// file the patterns above match.
func documentReaders(files map[string]string) []string {
	seen := map[string]bool{}
	for file, text := range files {
		if readsADocument.MatchString(text) || (climbs.MatchString(text) && walksForMd.MatchString(text)) {
			seen["./"+filepath.ToSlash(filepath.Dir(file))+"/"] = true
		}
	}
	var out []string
	for dir := range seen {
		out = append(out, dir)
	}
	sort.Strings(out)
	return out
}

// Every package whose tests read a document is tested by docs-check.
//
// That target is what a change to documents alone runs. A test elsewhere that
// reads one fails in CI for a prose edit the local gate passed.
func TestDocsCheckTestsEveryPackageThatReadsADocument(t *testing.T) {
	listed := regexp.MustCompile(`(?m)^DOCS_PACKAGES\s*:=(.*)$`).FindStringSubmatch(makefileText(t))
	if listed == nil {
		t.Fatal("the makefile declares no DOCS_PACKAGES, so this checked nothing")
	}
	tested := map[string]bool{}
	for _, dir := range strings.Fields(listed[1]) {
		tested[dir] = true
	}

	files := map[string]string{}
	root := filepath.Join("..", "..")
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "testdata" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(path, "_test.go") {
				body, err := os.ReadFile(path) //nolint:gosec // this repository's own source
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(root, path)
				files[rel] = string(body)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	readers := documentReaders(files)
	if len(readers) == 0 {
		t.Fatal("no test reads a document, so this checked nothing")
	}
	for _, dir := range readers {
		if !tested[dir] {
			t.Errorf("a test in %s reads a document and docs-check does not run it", dir)
		}
	}
}

// One test that reads a document by each spelling is found, and one that names
// a document as data, or keeps ".md" files without climbing out, is not.
func TestATestReadingADocumentIsFound(t *testing.T) {
	got := documentReaders(map[string]string{
		"internal/a/a_test.go": `os.ReadFile("../../docs/x.md")`,
		"internal/b/b_test.go": `os.ReadFile(filepath.Join("..", "..", "DESIGN-x.md"))`,
		"internal/c/c_test.go": `archive(map[string][]byte{"README.md": nil})`,
		"internal/d/d_test.go": `os.ReadFile(filepath.Join("..", "..", "docs", "x.md"))`,
		"internal/e/e_test.go": "root := filepath.Join(\"..\", \"..\")\nif filepath.Ext(path) != \".md\" {",
		"internal/f/f_test.go": `if filepath.Ext(path) != ".md" {`,
	})
	if strings.Join(got, ",") != "./internal/a/,./internal/b/,./internal/d/,./internal/e/" {
		t.Errorf("readers: %v, want internal/a, b, d and e", got)
	}
}
