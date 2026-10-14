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
	documented = regexp.MustCompile("`make ([a-z][a-z0-9-]*)(?:\\s[^`\n]*)?`")
	// A make command on a line of its own inside a code block, after a shell
	// prompt, and after variables set for the one run on either side of make.
	codeCommand = regexp.MustCompile(`^[ \t]*(?:\$[ \t]+)?(?:[A-Z_][A-Z0-9_]*=\S*[ \t]+)*make[ \t]+` +
		`(?:[A-Z_][A-Z0-9_]*=\S*[ \t]+)*([a-z][a-z0-9-]*)`)
	// The fence that opens or closes a code block.
	fence   = regexp.MustCompile("^[ \t]*(```|~~~)")
	printed = regexp.MustCompile(`"([a-z][a-z-]*)"`)
	named   = regexp.MustCompile("`internal/([a-z][a-z0-9/]*)/`")
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

// Every make command any document names is a target one of the makefiles
// defines, written bare or with its arguments.
//
// The build document is joined to the gate above. The rest of the documents
// name commands a reader types — the README, the operator pages, this
// repository's own instructions — and a renamed target leaves each of them
// sending a reader to "No rule to make target".
func TestEveryMakeCommandADocumentNamesIsATarget(t *testing.T) {
	defined := map[string]bool{}
	for _, name := range []string{"Makefile", "Makefile.demo"} {
		body, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // this repository's own makefiles
		if err != nil {
			t.Fatal(err)
		}
		_, targets := declarations(string(body))
		for target := range targets {
			defined[target] = true
		}
	}
	if len(defined) == 0 {
		t.Fatal("the makefiles define no targets, so this checked nothing")
	}
	root := filepath.Join("..", "..")
	described := 0
	err := filepath.WalkDir(root, func(at string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "node_modules", "bin", "dist", "site", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(at, ".md") {
			return nil
		}
		body, err := os.ReadFile(at) //nolint:gosec // a document of this repository
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, at)
		for _, name := range unknownCommands(string(body), defined, &described) {
			t.Errorf("%s names `make %s`, which no makefile defines", filepath.ToSlash(rel), name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if described == 0 {
		t.Fatal("no document names a make command, so this checked nothing")
	}
}

// unknownCommands is each target a document's make commands name that is not
// defined, counting every command it read into described.
//
// A command is read inline, in backticks, or on a line of its own inside a
// fenced code block, which is the form a reader copies. Prose outside a block
// is not read line by line, because "make the claim" opens a line as readily
// as a command does.
func unknownCommands(document string, defined map[string]bool, described *int) []string {
	var out []string
	read := func(target string) {
		*described++
		if !defined[target] {
			out = append(out, target)
		}
	}
	for _, found := range documented.FindAllStringSubmatch(document, -1) {
		read(found[1])
	}
	open := ""
	for _, line := range strings.Split(document, "\n") {
		if m := fence.FindStringSubmatch(line); m != nil {
			switch open {
			case "":
				open = m[1]
			case m[1]:
				open = ""
			}
			continue
		}
		if open == "" {
			continue
		}
		if m := codeCommand.FindStringSubmatch(line); m != nil {
			read(m[1])
		}
	}
	return out
}

// A command with arguments is read as its target, and an unknown one is
// reported.
func TestAMakeCommandWithArgumentsIsReadAsItsTarget(t *testing.T) {
	defined := map[string]bool{"release-check": true, "gate": true}
	described := 0
	got := unknownCommands("`make release-check VERSION=v1.0.0`, `make gate full` and `make typo ARG=1`",
		defined, &described)
	if strings.Join(got, ",") != "typo" || described != 3 {
		t.Errorf("unknown: %v of %d, want [typo] of 3", got, described)
	}
}

// A command on its own line in a code block is read, after a prompt or
// variables, and a line of prose outside one is not.
func TestAMakeCommandInACodeBlockIsReadAsItsTarget(t *testing.T) {
	defined := map[string]bool{"gate": true, "upgrade-rehearsal": true}
	described := 0
	document := "Run make the claim first.\n\n```sh\nmake gate\n$ make upgrade-rehearsal FROM=v0.7.0\n" +
		"OPENPSIRT_X=1 make scanner-dbx\nmake ARG=1 gone\n```\n\nmake prose here\n"
	got := unknownCommands(document, defined, &described)
	if strings.Join(got, ",") != "scanner-dbx,gone" || described != 4 {
		t.Errorf("unknown: %v of %d, want [scanner-dbx gone] of 4", got, described)
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
		"`make lint` and `test`, and `make typo`, and `make typo2 ARG=1`", defined)
	if strings.Join(gaps.unknown, ",") != "ghost,quiet" {
		t.Errorf("unknown: %v, want the two the makefile does not define", gaps.unknown)
	}
	if strings.Join(gaps.undescribed, ",") != "ghost,quiet" {
		t.Errorf("undescribed: %v, want the two the document does not name", gaps.undescribed)
	}
	if strings.Join(gaps.invented, ",") != "typo,typo2" {
		t.Errorf("invented: %v, want the two the makefile does not define", gaps.invented)
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
