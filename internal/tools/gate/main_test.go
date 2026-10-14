// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// This program decides which targets `make gate` runs, and had no test at all.
// A selection bug narrows the whole gate silently: every check it stopped
// choosing still passes, because it is not run.
//
// Both directions per case, which is what a gate test is for — one input that
// must reach a tier and one that must not.

func TestWhatATierIsChosenFrom(t *testing.T) {
	// Written into a directory of its own, because classify reads the file to
	// decide: whether it holds a query, and whether it registers an operation,
	// are questions about the contents rather than the name. The paths are
	// relative to it, as the gate's are to the checkout.
	dir := t.TempDir()
	t.Chdir(dir)
	write := func(name, content string) string {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return name
	}

	for _, c := range []struct {
		what string
		file string
		want []tier
	}{
		{"a design document", write("DESIGN-thing.md", "# Thing\n"), []tier{documents}},
		{"the interface's source, which the license check reads", "web/src/screens/Home.tsx", []tier{web, webPackages}},
		{"anything else under the interface", "web/scripts/check.mjs", []tier{web}},
		{"the module files", "go.mod", []tier{modules}},
		{"the interface's manifest", "web/package.json", []tier{web, webPackages}},
		{"the interface's lockfile", "web/package-lock.json", []tier{web, webPackages}},
		{"the makefile", "Makefile", []tier{everything}},
		{
			// The walk holds no SQL and registers no operation, so the code
			// tier would take it — and that tier does not run `reserved`.
			"a gate program", "internal/tools/walk/walk.go", []tier{everything},
		},
		{
			// Holds no SQL and registers no operation either, and moving the
			// version it requires changes what the linter and the scanners do.
			"a tool's pin", write("tools/golangci-lint/tools.go", "//go:build tools\n\npackage tools\n\n"+
				"import _ \"github.com/golangci/golangci-lint/v2/cmd/golangci-lint\"\n"),
			[]tier{everything},
		},
		{"the database package", "internal/database/connect.go", []tier{engines}},
		{"the test harness", "internal/dbtest/dbtest.go", []tier{engines}},
		{"the schema package", "internal/schema/indexes_test.go", []tier{engines}},
		{
			"go holding a query",
			write("store.go", "package p\n\nfunc read() { db.NewSelect().Model(&x) }\n"),
			[]tier{engines},
		},
		{
			"go holding SQL in a string",
			write("raw.go", "package p\n\nconst q = `SELECT 1 FROM thing`\n"),
			[]tier{engines},
		},
		{
			"go registering an operation",
			write("route.go", "package p\n\nfunc r() { huma.Register(api, huma.Operation{"+
				"OperationID: \"x\"}, h) }\n"),
			[]tier{api},
		},
		{
			// A field's description is written into the document, wherever
			// the type is declared.
			"go declaring a documented field",
			write("types.go", "package p\n\ntype X struct{ A int `json:\"a\" doc:\"x\"` }\n"),
			[]tier{api},
		},
		{
			// A type a route answers with changes the document through its
			// field names alone, with no tag to find.
			"any go in the package the document is generated from",
			write("internal/httpapi/shape.go", "package httpapi\n\ntype X struct{ A int }\n"),
			[]tier{api},
		},
		{
			"any go in a route package beneath it",
			write("internal/httpapi/core/shape.go", "package core\n\ntype X struct{ A int }\n"),
			[]tier{api},
		},
		{
			// A route file that also joins strings is both: the API document
			// is generated from it, and the query pattern matches it.
			"go in the API package that also reads as a query",
			write("internal/httpapi/both.go", "package httpapi\n\nfunc f() { strings.Join(nil, \"\") }\n"),
			[]tier{engines, api},
		},
		{
			"plain go",
			write("plain.go", "package p\n\nfunc add(a, b int) int { return a + b }\n"),
			[]tier{code},
		},
		{
			"a file that is not there any more", filepath.Join(dir, "gone.go"), []tier{everything},
		},
	} {
		if got := classify(c.file); !slices.Equal(got, c.want) {
			t.Errorf("%s classified as %v, want %v", c.what, names(got), names(c.want))
		}
	}
}

func TestTheTiersAboveDocumentsCarryTheOneBelow(t *testing.T) {
	// A change that moves a query is still Go, and has to compile and pass the
	// analysis gates before anything asks four engines about it.
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		at := filepath.Join(dir, name)
		if err := os.WriteFile(at, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return at
	}
	query := write("store.go", "package p\n\nfunc read() { db.NewSelect().Model(&x) }\n")
	route := write("route.go", "package p\n\nfunc r() { huma.Register(api, huma.Operation{"+
		"OperationID: \"x\"}, h) }\n")
	prose := write("DESIGN-thing.md", "# Thing\n")

	for _, c := range []struct {
		what  string
		files []string
		also  tier
		want  bool
	}{
		{"an API change is code too", []string{route}, code, true},
		{"an engine change is code too", []string{query}, code, true},
		{"a document change is not code", []string{prose}, code, false},
		{"an interface change is not code", []string{"web/src/app/App.tsx"}, code, false},
		{"the route table is code too", []string{"web/src/app/routes.json"}, code, true},
		{"the route table is the interface too", []string{"web/src/app/routes.json"}, web, true},
		{"a module change is code too", []string{"go.mod"}, code, true},
		{"a module change is the engines too", []string{"go.sum"}, engines, true},
		{"an interface manifest is not code", []string{"web/package.json"}, code, false},
	} {
		if got := tiers(c.files)[c.also]; got != c.want {
			t.Errorf("%s: reached %s = %v, want %v", c.what, name(c.also), got, c.want)
		}
	}
}

func TestTheGateNeverRunsBothFormsOfTheSameCheck(t *testing.T) {
	// The four-engine run subsumes the quick one, and the interface check ends
	// by regenerating the client — so choosing both is minutes of running the
	// same thing twice, and choosing neither is a check nobody notices is gone.
	for _, c := range []struct {
		what    string
		reached map[tier]bool
		absent  string
		present string
	}{
		{"four engines subsume the quick run", map[tier]bool{engines: true}, "test", "test-all"},
		{"the interface check subsumes the client", map[tier]bool{web: true}, "web-api", "web-check"},
	} {
		chosen := targets(c.reached)
		if slices.Contains(chosen, c.absent) {
			t.Errorf("%s: %q was chosen alongside %q: %v", c.what, c.absent, c.present, chosen)
		}
		if !slices.Contains(chosen, c.present) {
			t.Errorf("%s: %q was not chosen at all: %v", c.what, c.present, chosen)
		}
	}
}

func TestEverythingDelegatesToTheWholeGate(t *testing.T) {
	// The tier that exists so that a file nothing else understands still runs
	// everything. It names `check` rather than listing the narrower targets,
	// and the hazard is the reverse of the one below: reduced to a subset, the
	// checks it stopped choosing pass by not running.
	whole := targets(map[tier]bool{everything: true})
	// `check-packaging` among them, because it is the one tier CI runs and
	// the local gate did not — which is how a web build reaching outside
	// `web/` passed every check here and failed the image.
	for _, want := range []string{"check", "check-engines", "check-packaging"} {
		if !slices.Contains(whole, want) {
			t.Errorf("the everything tier chose %v, which leaves out %q", whole, want)
		}
	}
	// And only those: a narrower target chosen beside `check` is the same work
	// twice, which is what teaches people the gate is expensive.
	if len(whole) != 3 {
		t.Errorf("the everything tier chose %v alongside the whole gate", whole)
	}

	// Reaching everything alongside a narrower tier still runs everything
	// rather than the union, which would drop `check` for a longer list.
	with := targets(map[tier]bool{everything: true, code: true, web: true})
	if !slices.Contains(with, "check") {
		t.Errorf("everything plus a narrower tier chose %v, want the whole gate", with)
	}
}

func TestATargetInNoOrderStillRuns(t *testing.T) {
	// A target added to a tier and left out of the printed order must still be
	// chosen, rather than disappearing from the gate silently.
	runs[code] = append(runs[code], "a-target-nobody-ordered")
	t.Cleanup(func() { runs[code] = runs[code][:len(runs[code])-1] })

	if chosen := targets(map[tier]bool{code: true}); !slices.Contains(chosen, "a-target-nobody-ordered") {
		t.Errorf("a target left out of the order was left out of the gate: %v", chosen)
	}
}

func names(ts []tier) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, name(t))
	}
	return out
}

func TestEveryNarrowTierScansForSecrets(t *testing.T) {
	// Any file can carry a credential, and one pushed is in the remote's
	// history before CI reads it. The everything tier runs it inside check.
	checked := 0
	for tr, targets := range runs {
		if tr == everything || tr == api || tr == engines || tr == modules || tr == webPackages {
			continue
		}
		checked++
		if !slices.Contains(targets, "secrets") {
			t.Errorf("the %s tier runs %v, which leaves out the secret scan", name(tr), targets)
		}
	}
	if checked == 0 {
		t.Fatal("no narrow tier was examined, so this checked nothing")
	}
	// The tiers skipped above reach one that runs it.
	for _, tr := range []tier{api, engines, modules} {
		if !slices.Contains(targets(map[tier]bool{tr: true, code: true}), "secrets") {
			t.Errorf("the %s tier reaches no secret scan", name(tr))
		}
	}
	if !slices.Contains(targets(map[tier]bool{web: true, webPackages: true}), "secrets") {
		t.Error("the web packages tier reaches no secret scan")
	}
}

func TestEveryFileReadableReadsTakesATierRunningIt(t *testing.T) {
	// readable reads documents and the interface's source, so a control byte
	// pasted into either fails CI unless the tier the file lands in runs it.
	for _, file := range []string{"DESIGN-thing.md", "web/src/screens/Home.tsx", "web/scripts/check.mjs"} {
		reached := map[tier]bool{}
		for _, tr := range classify(file) {
			reached[tr] = true
		}
		if !slices.Contains(targets(reached), "readable") {
			t.Errorf("%s takes %v, which does not run readable", file, targets(reached))
		}
	}
}

func TestEveryTargetCheckRunsIsChosenBySomeTier(t *testing.T) {
	// A target check runs and no tier chooses is one a commit can fail in CI
	// with the local gate green, which is the narrowing the gate promises
	// never to do.
	makefile, err := os.ReadFile(filepath.Join("..", "..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	prerequisites := checkPrerequisites(string(makefile))
	if len(prerequisites) == 0 {
		t.Fatal("the makefile's check target lists no prerequisites, so this checked nothing")
	}
	for _, missing := range unchosenBy(prerequisites, runs) {
		t.Errorf("check runs %q and no narrow tier chooses it", missing)
	}
}

func TestATargetNoTierChoosesIsReported(t *testing.T) {
	tiers := map[tier][]string{code: {"build"}, everything: {"check"}}
	got := unchosenBy(checkPrerequisites("check: build lint\n\tdo\n"), tiers)
	if !slices.Equal(got, []string{"lint"}) {
		t.Errorf("unchosen: %v, want [lint]", got)
	}
}

// checkPrerequisites is what the makefile's check target depends on.
func checkPrerequisites(makefile string) []string {
	for _, line := range strings.Split(makefile, "\n") {
		if rest, ok := strings.CutPrefix(line, "check:"); ok {
			return strings.Fields(rest)
		}
	}
	return nil
}

// unchosenBy is each prerequisite no tier but everything runs.
func unchosenBy(prerequisites []string, tiers map[tier][]string) []string {
	var out []string
	for _, p := range prerequisites {
		found := false
		for tr, targets := range tiers {
			if tr != everything && slices.Contains(targets, p) {
				found = true
			}
		}
		if !found {
			out = append(out, p)
		}
	}
	return out
}
