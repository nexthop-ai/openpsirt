// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package build_test

import (
	"io/fs"
	"os"
	"path"
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
	named      = regexp.MustCompile("`internal/([a-z][a-z0-9/]*)/`")
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

// packages is every directory under internal holding a Go file that is not a
// test, as a path below internal, and every directory there at all.
func packages(t *testing.T) (withGo []string, dirs map[string]bool) {
	t.Helper()
	root := filepath.Join("..", "..", "internal")
	dirs = map[string]bool{}
	held := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// A fixture tree and the built interface are data, not packages.
			if d.Name() == "testdata" || d.Name() == "dist" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			dirs[rel] = true
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			held[filepath.ToSlash(filepath.Dir(rel))] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for dir := range held {
		withGo = append(withGo, dir)
	}
	sort.Strings(withGo)
	return withGo, dirs
}

// layoutGaps is every package the document names nowhere, and every path it
// names that is not there. A package is named by a row naming it or any
// directory above it, so a row for a parent covers what is inside.
func layoutGaps(packages []string, document string, exists func(string) bool) (unnamed, gone []string) {
	for _, pkg := range packages {
		covered := false
		for at := pkg; at != "." && at != ""; at = path.Dir(at) {
			if strings.Contains(document, "`internal/"+at+"/`") {
				covered = true
				break
			}
		}
		if !covered {
			unnamed = append(unnamed, pkg)
		}
	}
	for _, found := range named.FindAllStringSubmatch(document, -1) {
		if !exists(found[1]) {
			gone = append(gone, found[1])
		}
	}
	sort.Strings(unnamed)
	sort.Strings(gone)
	return unnamed, gone
}

// The one table that enumerates the tree names every package in it, at any
// depth, through its own row or one for a directory above it.
//
// It is where somebody looks to find out where something lives, so a package
// missing from it is a package they conclude is not there — and by this
// repository's own rule, code no document describes is a remnant somebody may
// delete.
func TestTheLayoutTableNamesEveryPackage(t *testing.T) {
	found, dirs := packages(t)
	if len(found) == 0 {
		t.Fatal("no packages were found under internal, so this checked nothing")
	}
	unnamed, gone := layoutGaps(found, buildDocument(t), func(dir string) bool { return dirs[dir] })
	if len(unnamed) > 0 {
		t.Errorf("under internal and named nowhere in DESIGN-build.md, so somebody looking for %s finds no row:\n  %s",
			plural(len(unnamed)), strings.Join(unnamed, "\n  "))
	}
	// The other direction, which is the one that rots quietly: a package is
	// renamed, the row that named it stays, and the table sends a reader
	// somewhere that is not there while every check stays green.
	if len(gone) > 0 {
		t.Errorf("named by DESIGN-build.md and not under internal, so the table sends a reader to %s:\n  %s",
			plural(len(gone)), strings.Join(gone, "\n  "))
	}
}

// Both directions of the layout check, given a document and a tree.
func TestALayoutGapIsReportedInBothDirections(t *testing.T) {
	document := "| `internal/a/` | a |\n| `internal/b/c/` | c |\n| `internal/gone/deeper/` | x |\n"
	tree := map[string]bool{"a": true, "a/inner": true, "b": true, "b/c": true, "d": true}
	unnamed, gone := layoutGaps([]string{"a", "a/inner", "b/c", "d"}, document,
		func(dir string) bool { return tree[dir] })
	if strings.Join(unnamed, ",") != "d" {
		t.Errorf("unnamed: %v, want [d] — a/inner is covered by its parent's row", unnamed)
	}
	if strings.Join(gone, ",") != "gone/deeper" {
		t.Errorf("gone: %v, want [gone/deeper]", gone)
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
	// The order slice is the whole set of names the gate prints. Found rather
	// than assumed: renaming it should report that this has stopped reading
	// anything, not slice a string at −1 and panic.
	opens := strings.Index(string(source), "var order = []string{")
	if opens < 0 {
		t.Fatal("the gate program declares no order slice, so this checked nothing")
	}
	order := source[opens:]
	closes := strings.Index(string(order), "}")
	if closes < 0 {
		t.Fatal("the gate program's order slice is not closed, so this checked nothing")
	}
	order = order[:closes]

	gaps := targetGaps(string(order), buildDocument(t), targets)
	if gaps.printed == 0 {
		t.Fatal("the gate prints no targets, so this checked nothing")
	}
	if gaps.described == 0 {
		t.Fatal("DESIGN-build.md names no make target, so this checked nothing")
	}
	if len(gaps.unknown) > 0 {
		t.Errorf("printed by the gate and defined by no target, so the gate would ask make for %s:\n  %s",
			plural(len(gaps.unknown)), strings.Join(gaps.unknown, "\n  "))
	}
	if len(gaps.undescribed) > 0 {
		t.Errorf("run by the gate and described nowhere in DESIGN-build.md, which reads as a remnant:\n  %s",
			strings.Join(gaps.undescribed, "\n  "))
	}
	if len(gaps.invented) > 0 {
		t.Errorf("described in DESIGN-build.md and defined by no target, so typing %s gets nothing:\n  %s",
			plural(len(gaps.invented)), strings.Join(gaps.invented, "\n  "))
	}
}

// targetJoin is what the join of the gate, the makefile and the document found.
type targetJoin struct {
	unknown, undescribed, invented []string
	printed, described             int
}

// targetGaps joins the names the gate prints, the targets the makefile
// defines and the targets the document describes, in every direction that
// can go wrong.
func targetGaps(order, document string, defined map[string]bool) targetJoin {
	var out targetJoin
	for _, found := range printed.FindAllStringSubmatch(order, -1) {
		out.printed++
		if !defined[found[1]] {
			out.unknown = append(out.unknown, found[1])
		}
		if !strings.Contains(document, "`"+found[1]+"`") &&
			!strings.Contains(document, "`make "+found[1]+"`") {
			out.undescribed = append(out.undescribed, found[1])
		}
	}
	for _, found := range documented.FindAllStringSubmatch(document, -1) {
		out.described++
		if !defined[found[1]] {
			out.invented = append(out.invented, found[1])
		}
	}
	sort.Strings(out.unknown)
	sort.Strings(out.undescribed)
	sort.Strings(out.invented)
	return out
}

// Each direction of the join, given inputs that must be reported.
func TestATargetGapIsReportedInEveryDirection(t *testing.T) {
	defined := map[string]bool{"lint": true, "test": true}
	gaps := targetGaps(`"lint", "test", "ghost", "quiet"`,
		"`make lint` and `test`, and `make typo`", defined)
	if strings.Join(gaps.unknown, ",") != "ghost,quiet" {
		t.Errorf("unknown: %v, want the two the makefile does not define", gaps.unknown)
	}
	if strings.Join(gaps.undescribed, ",") != "ghost,quiet" {
		t.Errorf("undescribed: %v, want the two the document does not name", gaps.undescribed)
	}
	if strings.Join(gaps.invented, ",") != "typo" {
		t.Errorf("invented: %v, want the one the makefile does not define", gaps.invented)
	}
	clean := targetGaps(`"lint"`, "`make lint`", defined)
	if len(clean.unknown)+len(clean.undescribed)+len(clean.invented) != 0 {
		t.Errorf("a clean join reported %+v", clean)
	}
}

func plural(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
