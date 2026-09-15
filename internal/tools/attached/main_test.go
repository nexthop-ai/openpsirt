package main

import "testing"

// This gate had no test, and its only consumer is a makefile line that reads
// an exit code. An exit code cannot tell a check that found nothing from a
// check that looked at nothing, so the detection is asked directly here: one
// input that must be reported and one that must not, per rule.

// inPackage is what a package declares, for the cases below.
func inPackage(names ...string) map[string]bool {
	declared := map[string]bool{}
	for _, name := range names {
		declared[name] = true
	}
	return declared
}

func TestACommentIsReportedOnlyWhereItDescribesAnotherSymbolOfItsPackage(t *testing.T) {
	for _, c := range []struct {
		what     string
		source   string
		declared map[string]bool
		want     int
	}{
		{
			"a comment left on the symbol it moved away from",
			`package p

// Widen takes a narrow thing and makes it wide.
func Narrow() {}

func Widen() {}
`,
			inPackage("Narrow", "Widen"),
			1,
		},
		{
			// The accident this exists for, and the one the same-file test
			// could not see: a file split leaves the block behind and the
			// symbol it names is now declared next door.
			"a comment naming a symbol that moved to another file of the package",
			`package p

// Widen takes a narrow thing and makes it wide.
func Narrow() {}
`,
			inPackage("Narrow", "Widen"),
			1,
		},
		{
			"a comment on its own declaration",
			`package p

// Narrow takes a wide thing and makes it narrow.
func Narrow() {}
`,
			inPackage("Narrow"),
			0,
		},
		{
			// The distinction the rule turns on. A first word that names
			// nothing in this package is prose, and reporting it would make
			// the gate fire on ordinary English.
			"prose that happens to open with a capitalized word",
			`package p

// PostgreSQL orders these differently, so the comparison is explicit.
func compare() {}
`,
			inPackage("compare"),
			0,
		},
		{
			// A verb nobody put on a list is still the convention's shape,
			// and the list left every comment using one unread.
			"a comment whose verb is not one anybody enumerated",
			`package p

// Widen unpicks a narrow thing.
func Narrow() {}
`,
			inPackage("Narrow", "Widen"),
			1,
		},
		{
			// A test's name is a sentence, so the convention does not apply
			// and its comment opens with whatever the test is about — very
			// often the symbol under test.
			"a test whose comment opens with the symbol it exercises",
			`package p

// Widen leaves the original alone.
func TestWidenLeavesTheOriginalAlone() {}
`,
			inPackage("Widen", "TestWidenLeavesTheOriginalAlone"),
			0,
		},
		{
			"a type whose comment describes a function beside it",
			`package p

// Resolve answers what a name points at.
type Resolver struct{}

func Resolve() {}
`,
			inPackage("Resolver", "Resolve"),
			1,
		},
		{
			"a var block whose comment names one of its own",
			`package p

// Limit is how many rows a page holds.
var Limit = 50
`,
			inPackage("Limit"),
			0,
		},
		{
			// Read at the group alone, every comment inside a const or var
			// block was unread — which is where a good part of this tree's
			// documentation is.
			"a comment on one spec inside a grouped declaration",
			`package p

const (
	// Widen is how wide a thing may get.
	Narrow = 1
	Widen  = 2
)
`,
			inPackage("Narrow", "Widen"),
			1,
		},
		{
			"a spec inside a grouped declaration whose comment is its own",
			`package p

const (
	// Narrow is how narrow a thing may get.
	Narrow = 1
	Widen  = 2
)
`,
			inPackage("Narrow", "Widen"),
			0,
		},
		{
			// The shape a block left behind takes once somebody corrects its
			// opening word to match the declaration under it: two docs on one
			// symbol, both rendered under one name, and the first about
			// something else.
			"two doc comments glued together with no blank line",
			`package p

// Narrow takes a wide thing and makes it narrow.
//
// It was here first.
// Narrow is the other one, which is the real doc.
func Narrow() {}
`,
			inPackage("Narrow"),
			1,
		},
		{
			// The ordinary shape, and it has to stay quiet: a doc comment
			// wraps, and a wrapped line beginning with the symbol's own name
			// mid-sentence is prose.
			"a doc comment that wraps onto a line beginning with its own name",
			`package p

// Narrow is the rule for the number: the rating somebody made, the published
// narrow score where there is none, and nothing where there is neither.
func Narrow() {}
`,
			inPackage("Narrow", "narrow"),
			0,
		},
		{
			// A run of constants introduced by a paragraph about the run is
			// how this tree groups them, and Go hands the whole block to the
			// first one. Its opening names no symbol, which is what tells it
			// from two docs glued together.
			"a paragraph introducing a run of constants",
			`package p

const (
	// The two kinds of thing, which differ in what they are counted against.
	//
	// Narrow is the first of them.
	Narrow = 1
	Widen  = 2
)
`,
			inPackage("Narrow", "Widen"),
			0,
		},
		{
			// A block separated from its declaration by another block is not
			// a doc comment at all: godoc shows it nowhere, and the thing it
			// was written for has none.
			"a comment block attached to nothing",
			`package p

// Widen takes a narrow thing and makes it wide.

// Narrow is the other one.
func Narrow() {}
`,
			inPackage("Narrow", "Widen"),
			1,
		},
		{
			// A file this tree opens with a paragraph about what the file is,
			// which is not a doc comment and is deliberate.
			"a file header naming what the file is about",
			`package p

// Narrow and what it is for, in one file.

import "fmt"

// Narrow takes a wide thing and makes it narrow.
func Narrow() { fmt.Println() }
`,
			inPackage("Narrow"),
			0,
		},
		{
			// A file the compiler will complain about, better than this can.
			"source that does not parse",
			"package p\n\nfunc (\n",
			inPackage(),
			0,
		},
	} {
		if got := detached("thing.go", []byte(c.source), c.declared); len(got) != c.want {
			t.Errorf("%s: reported %d (%v), want %d", c.what, len(got), got, c.want)
		}
	}
}

func TestOnlyWhatAPackageDeclaresAtItsTopLevelCountsAsASymbol(t *testing.T) {
	// A local variable and a struct field are named for what they hold in one
	// function or one record, and half the ordinary English words in this
	// tree are one of those somewhere. Reading them as symbols is what turns
	// the check into noise.
	declared := map[string]bool{}
	declares([]byte(`package p

type Record struct {
	Default string
}

func Build() {
	Reading := 1
	_ = Reading
}
`), declared)

	for _, want := range []string{"Record", "Build"} {
		if !declared[want] {
			t.Errorf("%s is declared at the top level and was not counted", want)
		}
	}
	for _, unwanted := range []string{"Default", "Reading"} {
		if declared[unwanted] {
			t.Errorf("%s is a field or a local and was counted as a symbol", unwanted)
		}
	}
}
