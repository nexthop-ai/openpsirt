package sbom_test

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The shape of a document is what it contains with everything it says
// discarded: the set of key paths and the type at each one. Two components of
// the same shape differ in what they state, not in what they are, which is why
// a document with thousands of components has very few shapes — and why the
// ones that appear once are the interesting ones.
//
// What this pins is not that the reader is right. It is what the reader has
// been shown. A path a producer emits that nothing here has decided about is
// the gap that matters: a field we do not read because we chose not to and one
// we do not read because we never knew it was there look identical in the
// code.

// pathsFile records every path the fixtures contain and what is done with it.
const pathsFile = "producer-paths.txt"

// realDocumentEnv points the same check at a full-size document, which is too
// large to keep in the repository. Absent means the check runs on the fixtures
// alone, and says so.
const realDocumentEnv = "OPENPSIRT_TEST_SBOM"

// update rewrites the record, adding paths it has not seen as undecided.
// Existing decisions are kept: the point is to make a new path visible, not to
// re-answer the ones already answered.
var update = flag.Bool("update", false, "add newly seen paths to "+pathsFile)

// decision is what has been decided about a path.
type decision string

const (
	// pathRead means the reader acts on it.
	pathRead decision = "read"
	// pathSkipped means the reader has seen it and does not act on it.
	pathSkipped decision = "skipped"
)

func TestEveryPathTheFixturesContainHasBeenDecidedAbout(t *testing.T) {
	decided := loadDecisions(t)
	seen := map[string]bool{}

	for _, name := range fixtureNames(t) {
		paths, shapes, components := documentPaths(t, name)
		t.Logf("%s: %d components, %d distinct shapes, %d paths", name, components, len(shapes), len(paths))
		for path := range paths {
			seen[path] = true
		}
	}

	if *update {
		writeDecisions(t, decided, seen)
		return
	}

	var undecided []string
	for path := range seen {
		if _, ok := decided[path]; !ok {
			undecided = append(undecided, path)
		}
	}
	sort.Strings(undecided)
	if len(undecided) > 0 {
		t.Errorf("a producer emits %d path(s) nothing has decided about:\n  %s\n\n"+
			"Read them, or record them as skipped: go test ./internal/sbom -update",
			len(undecided), strings.Join(undecided, "\n  "))
	}
}

func TestEveryPathTheReaderActsOnAppearsInAFixture(t *testing.T) {
	// A branch of the reader that no fixture reaches is untested, whatever the
	// coverage of the lines around it says.
	decided := loadDecisions(t)
	seen := map[string]bool{}
	for _, name := range fixtureNames(t) {
		paths, _, _ := documentPaths(t, name)
		for path := range paths {
			seen[path] = true
		}
	}

	var missing []string
	for path, what := range decided {
		if what == pathRead && !seen[path] {
			missing = append(missing, path)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the reader acts on %d path(s) no fixture contains:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

func TestAFullSizeDocumentIntroducesNoUndecidedPath(t *testing.T) {
	path := os.Getenv(realDocumentEnv)
	if path == "" {
		t.Skipf("%s is not set, so only the fixtures were checked — they are small by construction, "+
			"and the shapes that appear once are the ones a small document does not have", realDocumentEnv)
	}

	dir, name := filepath.Split(filepath.Clean(path))
	if dir == "" {
		dir = "."
	}
	f, err := os.OpenInRoot(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	paths, shapes, components := documentPaths(t, path, f)
	t.Logf("%s: %d components, %d distinct shapes, %d paths", path, components, len(shapes), len(paths))

	// The shapes carried by a single component are the ones a curated fixture
	// would never think to include.
	var once []string
	for shape, n := range shapes {
		if n == 1 {
			once = append(once, shape)
		}
	}
	t.Logf("%d shape(s) are carried by exactly one component", len(once))

	decided := loadDecisions(t)
	var undecided []string
	for p := range paths {
		if _, ok := decided[p]; !ok {
			undecided = append(undecided, fmt.Sprintf("%s (%d components)", p, paths[p]))
		}
	}
	sort.Strings(undecided)
	if len(undecided) > 0 {
		t.Errorf("a full-size document contains %d path(s) nothing has decided about:\n  %s",
			len(undecided), strings.Join(undecided, "\n  "))
	}
}

// fixtureNames lists the recorded documents.
func fixtureNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	return names
}

// documentPaths walks a document, returning how many components carry each
// path, how many components carry each shape, and how many there were.
//
// Components are decoded one at a time rather than all at once: a full-size
// document is tens of megabytes, and holding all of it as decoded values costs
// several times that.
func documentPaths(t *testing.T, name string, from ...io.Reader) (map[string]int, map[string]int, int) {
	t.Helper()

	var r io.Reader
	if len(from) > 0 {
		r = from[0]
	} else {
		f, err := os.OpenInRoot("testdata", name)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		r = f
	}

	paths := map[string]int{}
	shapes := map[string]int{}
	components := 0

	record := func(value any, prefix string) {
		for path := range walkPaths(value, prefix) {
			paths[path]++
		}
	}

	dec := json.NewDecoder(r)
	if _, err := dec.Token(); err != nil { // the opening brace
		t.Fatalf("%s: %v", name, err)
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		key, _ := tok.(string)
		if key != "components" {
			var value any
			if err := dec.Decode(&value); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			record(value, key)
			continue
		}
		if _, err := dec.Token(); err != nil { // the opening bracket
			t.Fatalf("%s: %v", name, err)
		}
		for dec.More() {
			var component any
			if err := dec.Decode(&component); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			components++
			var own []string
			for path := range walkPaths(component, "components[]") {
				paths[path]++
				own = append(own, path)
			}
			sort.Strings(own)
			shapes[strings.Join(own, " ")]++
		}
		if _, err := dec.Token(); err != nil { // the closing bracket
			t.Fatalf("%s: %v", name, err)
		}
	}
	return paths, shapes, components
}

// walkPaths returns every key path in a value, with the type found at it and
// the values themselves discarded.
//
// A segment repeated immediately — a component holding components — collapses
// into one, so a path describes the nesting that exists rather than how deep
// this particular document happened to go.
func walkPaths(value any, prefix string) map[string]bool {
	found := map[string]bool{}
	var walk func(any, string)
	walk = func(node any, at string) {
		switch v := node.(type) {
		case map[string]any:
			for key, child := range v {
				walk(child, join(at, key))
			}
		case []any:
			for _, child := range v {
				walk(child, join(at, "[]"))
			}
		case nil:
			found[at+":null"] = true
		case bool:
			found[at+":boolean"] = true
		case float64, json.Number:
			found[at+":number"] = true
		case string:
			found[at+":string"] = true
		}
	}
	walk(value, prefix)
	return found
}

// join adds a segment to a path, unless it repeats the one before it.
func join(at, segment string) string {
	if segment == "[]" {
		if strings.HasSuffix(at, "[]") {
			return at
		}
		return at + "[]"
	}
	if at == "" {
		return segment
	}
	if strings.HasSuffix(at, "."+segment) || at == segment {
		return at
	}
	return at + "." + segment
}

// loadDecisions reads what has been decided about each path.
func loadDecisions(t *testing.T) map[string]decision {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", pathsFile))
	if err != nil {
		t.Fatalf("%s: %v", pathsFile, err)
	}
	defer f.Close()

	decided := map[string]decision{}
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		what, path, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("%s: %q is neither a decision nor a path", pathsFile, line)
		}
		path = strings.TrimSpace(path)
		switch decision(what) {
		case pathRead, pathSkipped:
			decided[path] = decision(what)
		default:
			t.Fatalf("%s: %q is not a decision", pathsFile, what)
		}
	}
	return decided
}

// writeDecisions rewrites the record, keeping every decision already made and
// adding what has not been seen before as undecided.
func writeDecisions(t *testing.T, decided map[string]decision, seen map[string]bool) {
	t.Helper()
	for path := range seen {
		if _, ok := decided[path]; !ok {
			decided[path] = pathSkipped
		}
	}
	paths := make([]string, 0, len(decided))
	for path := range decided {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var b strings.Builder
	b.WriteString(`# What our producers emit, and what is done with it.
#
# One line per key path a recorded document contains, with the type found at
# it. "read" means the reader acts on it; "skipped" means it has been seen and
# deliberately left alone.
#
# A path in a document and not in this list fails the test. That is the point:
# a field nobody reads because it was never noticed and one nobody reads
# because it was considered look the same in the code, and only one of them is
# a decision.
#
# Add newly seen paths with: go test ./internal/sbom -update
`)
	for _, path := range paths {
		fmt.Fprintf(&b, "%s %s\n", decided[path], path)
	}
	if err := os.WriteFile(filepath.Join("testdata", pathsFile), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s with %d paths", pathsFile, len(paths))
}
