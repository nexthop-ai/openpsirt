package main

import (
	"os"
	"path/filepath"
	"slices"
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
	// are questions about the contents rather than the name.
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		at := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(at), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(at, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return at
	}

	for _, c := range []struct {
		what string
		file string
		want tier
	}{
		{"a design document", write("DESIGN-thing.md", "# Thing\n"), documents},
		{"anything under the interface", "web/src/screens/Home.tsx", web},
		{"the module files", "go.mod", engines},
		{"the makefile", "Makefile", everything},
		{
			// The walk holds no SQL and registers no operation, so the code
			// tier would take it — and that tier does not run `reserved`.
			"a gate program", "internal/tools/walk/walk.go", everything,
		},
		{"the database package", "internal/database/connect.go", engines},
		{"the test harness", "internal/dbtest/dbtest.go", engines},
		{"the schema package", "internal/schema/indexes_test.go", engines},
		{
			"go holding a query",
			write("store.go", "package p\n\nfunc read() { db.NewSelect().Model(&x) }\n"),
			engines,
		},
		{
			"go holding SQL in a string",
			write("raw.go", "package p\n\nconst q = `SELECT 1 FROM thing`\n"),
			engines,
		},
		{
			"go registering an operation",
			write("route.go", "package p\n\nfunc r() { huma.Register(api, huma.Operation{"+
				"OperationID: \"x\"}, h) }\n"),
			api,
		},
		{
			"plain go",
			write("plain.go", "package p\n\nfunc add(a, b int) int { return a + b }\n"),
			code,
		},
		{
			"a file that is not there any more", filepath.Join(dir, "gone.go"), everything,
		},
	} {
		if got := classify(c.file); got != c.want {
			t.Errorf("%s classified as %s, want %s", c.what, name(got), name(c.want))
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
