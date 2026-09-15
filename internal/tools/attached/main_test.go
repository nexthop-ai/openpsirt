package main

import "testing"

// This gate had no test, and its only consumer is a makefile line that reads
// an exit code. An exit code cannot tell a check that found nothing from a
// check that looked at nothing, so the detection is asked directly here: one
// input that must be reported and one that must not, per rule.

func TestACommentIsReportedOnlyWhereItDescribesSomethingElseInTheFile(t *testing.T) {
	for _, c := range []struct {
		what   string
		source string
		want   int
	}{
		{
			"a comment left on the symbol it moved away from",
			`package p

// Widen takes a narrow thing and makes it wide.
func Narrow() {}

func Widen() {}
`,
			1,
		},
		{
			"a comment on its own declaration",
			`package p

// Narrow takes a wide thing and makes it narrow.
func Narrow() {}
`,
			0,
		},
		{
			// The distinction the rule turns on. A capitalized first word that
			// names nothing here is prose, and reporting it would make the
			// gate fire on ordinary English.
			"prose that happens to open with a capitalized word",
			`package p

// PostgreSQL orders these differently, so the comparison is explicit.
func compare() {}
`,
			0,
		},
		{
			"a type whose comment describes a function beside it",
			`package p

// Resolve answers what a name points at.
type Resolver struct{}

func Resolve() {}
`,
			1,
		},
		{
			"a var block whose comment names one of its own",
			`package p

// Limit is how many rows a page holds.
var Limit = 50
`,
			0,
		},
		{
			// A file the compiler will complain about, better than this can.
			"source that does not parse",
			"package p\n\nfunc (\n",
			0,
		},
	} {
		if got := detached("thing.go", []byte(c.source)); len(got) != c.want {
			t.Errorf("%s: reported %d (%v), want %d", c.what, len(got), got, c.want)
		}
	}
}
