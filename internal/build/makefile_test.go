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

// Every target is declared phony and every declaration names a target.
//
// The convention is the whole list, not most of it, and it drifts in both
// directions: a declaration outlives the target it named, and a target added
// beside its siblings is not added to the list above them. Neither is visible
// until a file of that name exists in the checkout, and then the target
// reports "up to date" and runs nothing.
func TestEveryTargetIsDeclaredPhonyAndEveryDeclarationNamesOne(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "Makefile*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no makefiles were found, so this checked nothing")
	}
	examined := 0
	for _, path := range paths {
		body, err := os.ReadFile(path) //nolint:gosec // this repository's own makefiles
		if err != nil {
			t.Fatal(err)
		}
		phony, targets := declarations(string(body))
		if len(targets) == 0 {
			t.Fatalf("%s defines no targets, so this checked nothing", filepath.Base(path))
		}
		examined += len(targets)
		if names := missing(targets, phony); len(names) > 0 {
			t.Errorf("%s defines %v and does not declare them phony", filepath.Base(path), names)
		}
		if names := missing(phony, targets); len(names) > 0 {
			t.Errorf("%s declares %v phony and defines no such target", filepath.Base(path), names)
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
