// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package docs_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// A published page names the release a reader deploys as {{ release }}, which
// the documentation build fills in from the tag. A version written out by hand
// is the one nobody moves when the next release is cut, and a reader who
// copies it deploys something stale.

var (
	// Three numeric parts, with or without a leading v. What sits either side
	// is checked separately, because a network address has four parts and a
	// package version such as 1.1.1w runs on into a letter.
	releaseShape = regexp.MustCompile(`v?\d+\.\d+\.\d+`)
	// The upgrade notes, where past releases are the subject: a "From vX.Y.Z"
	// heading and everything beneath it up to the next heading at its level
	// or above.
	upgradeNote = regexp.MustCompile(`^###\s+From v\d+\.\d+\.\d+\s*$`)
	sectionEnd  = regexp.MustCompile(`^#{1,3}\s`)
)

// notReleases are versions a page shows that belong to something else, keyed
// by the page. Each is a third party's version or a customer's tag in an
// example.
var notReleases = map[string][]string{
	"docs/pipeline.md": {
		"v2.4.1", // a product tag in the stream examples
		"8.4.0",  // curl, in an inventory comparison
		"1.3.1",  // zlib, in the same comparison
	},
	"docs/vendor-release.md": {
		"8.5.0", // curl, in a statement's example
	},
}

// releaseLiterals returns every version-shaped literal in a page that is not
// exempt from naming a release.
func releaseLiterals(name, text string) []string {
	var found []string
	inNote := false
	for line := range strings.SplitSeq(text, "\n") {
		if name == "docs/configuration.md" {
			switch {
			case upgradeNote.MatchString(line):
				inNote = true
				continue
			case sectionEnd.MatchString(line):
				inNote = false
			}
		}
		if inNote {
			continue
		}
		for _, at := range releaseShape.FindAllStringIndex(line, -1) {
			if at[0] > 0 {
				if before := line[at[0]-1]; isDigit(before) || before == '.' {
					continue
				}
			}
			if rest := line[at[1]:]; rest != "" {
				if isLetter(rest[0]) || (rest[0] == '.' && len(rest) > 1 && isDigit(rest[1])) {
					continue
				}
			}
			literal := line[at[0]:at[1]]
			if slices.Contains(notReleases[name], literal) {
				continue
			}
			found = append(found, literal)
		}
	}
	return found
}

func isDigit(b byte) bool  { return b >= '0' && b <= '9' }
func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

// publishedPages is every page a reader of the site or the repository meets,
// keyed by its path from the root.
func publishedPages(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	pages := map[string]string{}
	for _, name := range []string{"README.md", "SECURITY.md"} {
		text, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // this repository's own documents
		if err != nil {
			t.Fatal(err)
		}
		pages[name] = string(text)
	}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".md" {
			return err
		}
		text, err := os.ReadFile(path) //nolint:gosec // walking this repository's own documents
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		pages[filepath.ToSlash(rel)] = string(text)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return pages
}

func TestPublishedPagesNameNoReleaseByHand(t *testing.T) {
	pages := publishedPages(t)
	site := 0
	for name := range pages {
		if strings.HasPrefix(name, "docs/") {
			site++
		}
	}
	if site == 0 {
		t.Fatal("no page under docs/ was found, so this checked nothing")
	}
	for name, text := range pages {
		for _, literal := range releaseLiterals(name, text) {
			t.Errorf("%s names %s by hand: write {{ release }} for the release a reader deploys, "+
				"or say what holds without naming one", name, literal)
		}
	}
	for name := range notReleases {
		if _, ok := pages[name]; !ok {
			t.Errorf("%s has exemptions and is not a published page", name)
		}
	}
}

// A page names the scanner the image carries as {{ scanner }}, and its pinned
// checksums likewise, which the documentation build fills in from the
// Dockerfile. The names a page may write are the ones the hook declares, read
// from its source here; the hook fails the build on any other, and on a
// declared name it does not fill. A placeholder no page writes, or one the
// Dockerfile does not pin exactly once, is reported too.
func TestEveryPlaceholderIsOneTheBuildFills(t *testing.T) {
	hook, err := os.ReadFile(filepath.Join("..", "..", "docs", "hooks", "release.py"))
	if err != nil {
		t.Fatal(err)
	}
	declared := regexp.MustCompile(`(?m)^PLACEHOLDERS = \(([^)]*)\)`).FindSubmatch(hook)
	if declared == nil {
		t.Fatal("the hook declares no placeholders, so this checked nothing")
	}
	known := map[string]bool{}
	for _, found := range regexp.MustCompile(`"([a-z0-9_]+)"`).FindAllSubmatch(declared[1], -1) {
		known[string(found[1])] = true
	}
	if len(known) == 0 {
		t.Fatal("the hook declares no placeholders, so this checked nothing")
	}

	// The hook's own pattern: a workflow expression, ${{ matrix.variant }}, in
	// a pipeline example follows a dollar sign and holds a dot.
	placeholder := regexp.MustCompile(`(?:^|[^$])\{\{\s*([a-z0-9_]+)\s*\}\}`)
	seen := map[string]bool{}
	for name, text := range publishedPages(t) {
		for _, found := range placeholder.FindAllStringSubmatch(text, -1) {
			seen[found[1]] = true
			if !known[found[1]] {
				t.Errorf("%s writes {{ %s }}, which the documentation build does not fill in", name, found[1])
			}
		}
	}
	for name := range known {
		if !seen[name] {
			t.Errorf("no page writes {{ %s }}, so this checked less than it says", name)
		}
	}

	dockerfile, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	// The stage that fetches the scanner, as the hook reads it: another stage
	// pins another tool's checksums the same way.
	stage := regexp.MustCompile(`(?ms)^FROM \S+ AS scanner$(.*?)^FROM `).FindSubmatch(dockerfile)
	if stage == nil {
		t.Fatal("the Dockerfile has no scanner stage, so this checked nothing")
	}
	dockerfile = stage[1]
	for what, pin := range map[string]string{
		"the scanner":                  `(?m)^ARG GRYPE_VERSION=\d+\.\d+\.\d+\s*$`,
		"the scanner's amd64 checksum": `(?m)^\s*amd64\) expected=[0-9a-f]{64} ;;`,
		"the scanner's arm64 checksum": `(?m)^\s*arm64\) expected=[0-9a-f]{64} ;;`,
	} {
		if n := len(regexp.MustCompile(pin).FindAll(dockerfile, -1)); n != 1 {
			t.Errorf("the Dockerfile pins %s %d times, and the pages need exactly one", what, n)
		}
	}
}

func TestReleaseLiteralsAreToldFromWhatIsNotARelease(t *testing.T) {
	reported := []struct{ name, text, want string }{
		{"docs/trying.md", "  ghcr.io/nexthop-ai/openpsirt:0.2.0\n", "0.2.0"},
		{"docs/trying.md", "as `openpsirt-0.2.0.tgz` on the release", "0.2.0"},
		{"README.md", "A database built by v0.1.0 is upgraded", "v0.1.0"},
		{"docs/built.md", "The latest release is 0.4.0.", "0.4.0"},
		{"docs/built.md", "a candidate, v0.5.0-rc.1, is tried", "v0.5.0"},
		{"docs/configuration.md", "## Upgrading\n\nA v0.3.0 database is current.\n", "v0.3.0"},
		{"docs/configuration.md", "### From v0.1.0\n\nbody\n\n## Serving\n\nrun v0.4.0\n", "v0.4.0"},
		{"docs/configuration.md", "### From v0.1.0\n\nbody\n\n### Every upgrade\n\nrun v0.4.0\n", "v0.4.0"},
		{"docs/index.md", "curl 8.4.0 in an example", "8.4.0"},
	}
	for _, c := range reported {
		if got := releaseLiterals(c.name, c.text); !slices.Equal(got, []string{c.want}) {
			t.Errorf("%s %q: reported %q, want [%s]", c.name, c.text, got, c.want)
		}
	}

	exempt := []struct{ name, text string }{
		{"docs/trying.md", "ghcr.io/nexthop-ai/openpsirt:{{ release }}"},
		{"docs/trying.md", `-e OPENPSIRT_ADDR="0.0.0.0:8080"`},
		{"docs/configuration.md", "OPENPSIRT_OUTBOUND_EXCLUDED=corp.example.com,203.0.113.0/24"},
		{"docs/configuration.md", "### From v0.2.0\n\nv0.2.0 read only the new name.\n\n#### Detail\n\nv0.1.0 too\n"},
		{"docs/pipeline.md", `{"name": "v2.4.1", "kind": "tag"}`},
		{"docs/pipeline.md", `"before": ["1.1.1w"]`},
		{"README.md", "CycloneDX 1.7 and SPDX 2.3, below 1.0"},
	}
	for _, c := range exempt {
		if got := releaseLiterals(c.name, c.text); len(got) != 0 {
			t.Errorf("%s %q: reported %q, which is not a release named by hand", c.name, c.text, got)
		}
	}
}
