package main

import (
	"go/parser"
	"go/token"
	"testing"
)

// Exported code with no caller is a defect rather than spare capacity — a
// store method nothing routes to, a renderer nothing renders with. This is the
// gate AGENTS.md leans on for that, and it had no test.

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
	// Only functions were read, so a request type registered on no operation
	// sat fully specified and unreachable — in neither the OpenAPI document
	// nor the generated client, because nothing put it there. A type is the
	// shape this gate is least able to be talked out of: it compiles, it reads
	// as intent, and nothing calls it.
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
