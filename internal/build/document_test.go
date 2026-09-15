package build_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A make target the build document names, and a target name the gate program
// prints.
var (
	documented = regexp.MustCompile("`make ([a-z][a-z-]*)`")
	printed    = regexp.MustCompile(`"([a-z][a-z-]*)"`)
)

// buildDocument returns DESIGN-build.md, which is the one document that
// enumerates the tree and the gate.
func buildDocument(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "DESIGN-build.md")) //nolint:gosec // this repository's own document
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// The one table that enumerates the tree names every package in it.
//
// It is where somebody looks to find out where something lives, so a package
// missing from it is a package they conclude is not there — and by this
// repository's own rule, code no document describes is a remnant somebody may
// delete.
func TestTheLayoutTableNamesEveryPackage(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatal(err)
	}
	document := buildDocument(t)
	var unnamed []string
	packages := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		packages++
		if !strings.Contains(document, "`internal/"+entry.Name()+"/`") {
			unnamed = append(unnamed, entry.Name())
		}
	}
	if packages == 0 {
		t.Fatal("no packages were found under internal, so this checked nothing")
	}
	sort.Strings(unnamed)
	if len(unnamed) > 0 {
		t.Errorf("under internal and named nowhere in DESIGN-build.md, so somebody looking for %s finds no row:\n  %s",
			plural(len(unnamed)), strings.Join(unnamed, "\n  "))
	}
}

// Every target the gate can run is a target the makefile has and the build
// document describes, and every target the document describes exists.
//
// The gate prints target names for make to run, so a name it prints that the
// makefile does not define is a gate that fails where it should have run — and
// a target described in the document and defined nowhere is a command somebody
// types and does not get.
func TestTheGateTheMakefileAndTheDocumentNameTheSameTargets(t *testing.T) {
	makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile")) //nolint:gosec // this repository's own makefile
	if err != nil {
		t.Fatal(err)
	}
	_, targets := declarations(string(makefile))
	if len(targets) == 0 {
		t.Fatal("the makefile defines no targets, so this checked nothing")
	}

	source, err := os.ReadFile(filepath.Join("..", "tools", "gate", "main.go")) //nolint:gosec // this repository's own source
	if err != nil {
		t.Fatal(err)
	}
	// The order slice is the whole set of names the gate prints, and it is the
	// last one in the file that is a list of target names.
	order := source[strings.Index(string(source), "var order = []string{"):]
	order = order[:strings.Index(string(order), "}")]
	document := buildDocument(t)

	var unknown, undescribed []string
	named := 0
	for _, found := range printed.FindAllStringSubmatch(string(order), -1) {
		named++
		if !targets[found[1]] {
			unknown = append(unknown, found[1])
		}
		if !strings.Contains(document, "`"+found[1]+"`") &&
			!strings.Contains(document, "`make "+found[1]+"`") {
			undescribed = append(undescribed, found[1])
		}
	}
	if named == 0 {
		t.Fatal("the gate prints no targets, so this checked nothing")
	}
	sort.Strings(unknown)
	sort.Strings(undescribed)
	if len(unknown) > 0 {
		t.Errorf("printed by the gate and defined by no target, so the gate would ask make for %s:\n  %s",
			plural(len(unknown)), strings.Join(unknown, "\n  "))
	}
	if len(undescribed) > 0 {
		t.Errorf("run by the gate and described nowhere in DESIGN-build.md, which reads as a remnant:\n  %s",
			strings.Join(undescribed, "\n  "))
	}

	var invented []string
	for _, found := range documented.FindAllStringSubmatch(document, -1) {
		if !targets[found[1]] {
			invented = append(invented, found[1])
		}
	}
	sort.Strings(invented)
	if len(invented) > 0 {
		t.Errorf("described in DESIGN-build.md and defined by no target, so typing %s gets nothing:\n  %s",
			plural(len(invented)), strings.Join(invented, "\n  "))
	}
}

func plural(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
