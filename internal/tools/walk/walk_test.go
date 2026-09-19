package walk

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The reader all six gate programs route through, and it had no test.
//
// The cost is specific: a gate whose walk reaches nothing prints the
// same all-clear as one that read the whole tree and found nothing wrong, and
// the refusal that tells those apart had never been seen to fire. AGENTS.md:
// "A control whose test has never been seen to fail is a control nobody has
// tested."

// tree builds a small repository to walk and changes into it, because the
// walk is rooted at the working directory on purpose: a program that walks
// wherever it is pointed is a shape worth not having.
func tree(t *testing.T, files map[string]string) {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	was, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(was); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAWalkThatReachesNothingRefuses(t *testing.T) {
	// The whole point. An empty result is what "nothing is wrong" looks like
	// and what "I read nothing" looks like, so the second has to be an error
	// rather than a silence — no caller can tell them apart from a count of
	// zero.
	tree(t, map[string]string{"main.go": "package main"})

	reached := 0
	read, err := Only(".mjs", nil, func(string, []byte) error {
		reached++
		return nil
	})
	if err == nil {
		t.Fatal("a walk that read no file answered no error, so a gate over it " +
			"would print the same all-clear as one that read the whole tree")
	}
	if read != 0 || reached != 0 {
		t.Errorf("read %d and visited %d, wanted neither", read, reached)
	}
}

func TestPathsCountsWhatTheCallerKeptRatherThanWhatItWasShown(t *testing.T) {
	// A count of visits would be held above zero by any file at all — a
	// licence, a readme — so a gate that reads one kind of file could never
	// reach the refusal above. What it keeps is what it checked.
	tree(t, map[string]string{
		"LICENSE":            "a licence",
		"README.md":          "prose",
		"internal/notes.txt": "not markdown",
	})

	kept, err := Paths(nil, func(path string) (bool, error) {
		return filepath.Ext(path) == ".md", nil
	})
	if err != nil {
		t.Fatalf("a walk that kept one file refused: %v", err)
	}
	if kept != 1 {
		t.Errorf("kept %d, want the one markdown file", kept)
	}

	// And a caller that keeps nothing is refused, however many it was shown.
	if _, err := Paths(nil, func(string) (bool, error) { return false, nil }); err == nil {
		t.Error("a walk whose caller kept nothing answered no error")
	}
}

func TestTheDefaultSkipSetIsMatchedByDirectoryName(t *testing.T) {
	// By name at any depth rather than by path prefix, because that is what a
	// caller adding "web" or "vendor" means — and because node_modules nests.
	tree(t, map[string]string{
		"a.go":                        "package a",
		"node_modules/x/b.go":         "package b",
		"web/node_modules/y/c.go":     "package c",
		"internal/dist/d.go":          "package d",
		".git/hooks/e.go":             "package e",
		"internal/tools/walk/walk.go": "package walk",
	})

	var seen []string
	read, err := Sources(".go", func(path string, _ []byte) error {
		seen = append(seen, filepath.ToSlash(path))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(seen)
	want := []string{"a.go", "internal/tools/walk/walk.go"}
	if read != len(want) || !slices.Equal(seen, want) {
		t.Errorf("read %v, want %v — a skipped name must be skipped at any depth", seen, want)
	}
}

func TestWhatACallerAddsIsSkippedToo(t *testing.T) {
	// The five Go gates pass "web" and readable passes "vendor", each with
	// the reason at the call site. If extra did not reach the walk they would
	// all silently read more than they say they do.
	tree(t, map[string]string{
		"a.go":            "package a",
		"web/b.go":        "package b",
		"vendor/lib/c.go": "package c",
	})

	var seen []string
	read, err := Only(".go", []string{"web", "vendor"}, func(path string, _ []byte) error {
		seen = append(seen, filepath.ToSlash(path))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if read != 1 || len(seen) != 1 || seen[0] != "a.go" {
		t.Errorf("read %v, want a.go alone", seen)
	}
}

func TestTheDefaultSkipSetIsNotSharedBetweenCallers(t *testing.T) {
	// Skipped returns a fresh slice, which is what makes the append inside
	// each() safe: a shared backing array would let one caller's extra reach
	// the next caller's walk, and the next caller would read less than it
	// says it does with nothing failing.
	first, second := Skipped(), Skipped()
	if widened := append(first, "web"); slices.Contains(second, "web") {
		t.Errorf("appending to one caller's skip set reached another's: %v", widened)
	}
	if len(Skipped()) == 0 {
		t.Fatal("the default skip set is empty, so nothing would ever be skipped")
	}
}

func TestAPathCarriesNoLeadingDotSlash(t *testing.T) {
	// Every gate prints these, and somebody pastes one back into an editor.
	tree(t, map[string]string{"internal/a.go": "package a"})
	if _, err := Sources(".go", func(path string, _ []byte) error {
		if filepath.ToSlash(path) != "internal/a.go" {
			t.Errorf("visited %q", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
