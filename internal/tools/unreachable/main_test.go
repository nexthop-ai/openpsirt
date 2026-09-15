package main

import "testing"

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
