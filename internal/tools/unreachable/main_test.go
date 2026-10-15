// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// Exported code with no caller is a defect rather than spare capacity — a
// store method nothing routes to, a renderer nothing renders with. This is the
// gate AGENTS.md leans on for that.

func TestTheNamesTheRuntimeCallsAreNotOrphans(t *testing.T) {
	// A method satisfying a standard interface is reached by the runtime
	// rather than by anything written here, so it is written once and named
	// nowhere — which is exactly the shape an orphan has.
	for _, c := range []struct {
		name string
		want bool
	}{
		{"Error", true},
		{"String", true},
		{"Unwrap", true},
		{"Is", true},
		{"As", true},
		{"MarshalJSON", true},
		{"UnmarshalJSON", true},
		{"MarshalText", true},
		{"UnmarshalText", true},
		{"ServeHTTP", true},
		{"Read", true},
		{"Write", true},
		{"Close", true},
		{"Len", true},
		{"Less", true},
		{"Swap", true},

		// And the other direction, which is the half that matters: an
		// exemption that grew to cover ordinary names would make the gate
		// quiet about the symbols it exists to find.
		{"Record", false},
		{"Errors", false},
		{"Reader", false},
		{"WriteExport", false},
		{"Closed", false},
		{"Length", false},
		{"", false},
	} {
		if got := satisfiesSomething(c.name); got != c.want {
			t.Errorf("%q exempt = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestWhatCountsAsAnExportedDeclaration(t *testing.T) {
	// A request type registered on no operation is fully specified and
	// unreachable — in neither the OpenAPI document nor the generated client.
	// A type is the shape this gate is least able to be talked out of: it
	// compiles, it reads as intent, and nothing calls it.
	for _, c := range []struct {
		what   string
		source string
		want   []string
	}{
		{"an exported function", "package p\n\nfunc Open() {}\n", []string{"Open"}},
		{"an unexported one", "package p\n\nfunc open() {}\n", nil},
		{"an exported type", "package p\n\ntype Body struct{}\n", []string{"Body"}},
		{"an unexported type", "package p\n\ntype body struct{}\n", nil},
		{"an exported constant", "package p\n\nconst Limit = 50\n", []string{"Limit"}},
		{"an exported variable", "package p\n\nvar Schemes = 1\n", []string{"Schemes"}},
		{
			"a block declaring several",
			"package p\n\nconst (\n\tOne = 1\n\ttwo = 2\n\tThree = 3\n)\n",
			[]string{"One", "Three"},
		},
		{
			"a var block with two names on one line",
			"package p\n\nvar One, two = 1, 2\n",
			[]string{"One"},
		},
		{"an import, which declares nothing of ours", "package p\n\nimport \"fmt\"\n", nil},
	} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "thing.go", c.source, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		var got []string
		for _, d := range file.Decls {
			got = append(got, exportedIn(d)...)
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: read %v, want %v", c.what, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: read %v, want %v", c.what, got, c.want)
				break
			}
		}
	}
}

func TestAnOrphanIsReportedAndReadingNothingIsRefused(t *testing.T) {
	declared := []decl{{"p", "Used", "a.go", 3}, {"p", "Alone", "a.go", 1}, {"", "String", "a.go", 2}}
	seen := newCounts()
	seen.symbols[key{"p", "Used"}] = 2
	seen.symbols[key{"p", "Alone"}] = 1
	seen.names["String"] = 1
	got, err := orphansOf(declared, seen)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].name != "Alone" {
		t.Errorf("reported %v, want only the symbol nothing else names", got)
	}
	if _, err := orphansOf(nil, newCounts()); err == nil {
		t.Error("a walk that declared nothing was read as a clean tree")
	}
}

// orphansIn runs the gate over sources keyed by path, as the walk hands them
// over.
func orphansIn(t *testing.T, sources map[string]string) []decl {
	t.Helper()
	fset := token.NewFileSet()
	var declared []decl
	seen := newCounts()
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, sources[path], 0)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		declared = append(declared, declaredIn(fset, path, file)...)
		seen.add(path, file)
	}
	got, err := orphansOf(declared, seen)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestANameAnotherPackageSharesDoesNotHideAnOrphan(t *testing.T) {
	got := orphansIn(t, map[string]string{
		"internal/a/a.go": "package a\n\nfunc Two() {}\n",
		"internal/b/b.go": "package b\n\nfunc Two() {}\n",
		"internal/c/c.go": "package c\n\nimport \"" + module + "/internal/b\"\n\nfunc use() { b.Two() }\n",
	})
	if len(got) != 1 || got[0].file != "internal/a/a.go" || got[0].name != "Two" {
		t.Errorf("reported %v, want only the Two nothing calls", got)
	}
}

func TestAQualifiedReferenceResolvesThroughItsImport(t *testing.T) {
	for _, c := range []struct {
		what   string
		caller string
	}{
		{"an aliased import", "package c\n\nimport other \"" + module + "/internal/b\"\n\nfunc use() { other.Two() }\n"},
		{"a dot import", "package c\n\nimport . \"" + module + "/internal/b\"\n\nfunc use() { Two() }\n"},
		{"a bare name in the declaring package", ""},
	} {
		sources := map[string]string{
			"internal/b/b.go": "package b\n\nfunc Two() {}\n",
		}
		if c.caller == "" {
			sources["internal/b/use.go"] = "package b\n\nfunc use() { Two() }\n"
		} else {
			sources["internal/c/c.go"] = c.caller
		}
		if got := orphansIn(t, sources); len(got) != 0 {
			t.Errorf("%s: reported %v, want the call to count", c.what, got)
		}
	}
}

func TestANameAnExternalTestPackageWritesBareIsItsOwn(t *testing.T) {
	// An external test package declares its own names, so a bare Two there
	// is not a call of the package it tests.
	got := orphansIn(t, map[string]string{
		"internal/b/b.go":      "package b\n\nfunc Two() {}\n",
		"internal/b/b_test.go": "package b_test\n\nfunc Two() {}\n\nfunc use() { Two() }\n",
	})
	if len(got) != 1 || got[0].name != "Two" {
		t.Errorf("reported %v, want the package's Two", got)
	}
}

func TestAMethodIsMatchedByNameAlone(t *testing.T) {
	got := orphansIn(t, map[string]string{
		"internal/b/b.go": "package b\n\ntype T struct{}\n\nfunc (T) Run() {}\n\nfunc (T) Idle() {}\n\nvar V T\n",
		"internal/c/c.go": "package c\n\nimport \"" + module + "/internal/b\"\n\nfunc use() { b.V.Run() }\n",
	})
	if len(got) != 1 || got[0].name != "Idle" {
		t.Errorf("reported %v, want only the method nothing names", got)
	}
}
