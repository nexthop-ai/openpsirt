// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package bound_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/bound"
)

func TestACharacterBoundKeepsTheCharactersTheColumnHolds(t *testing.T) {
	// The indexed name columns are declared in characters, and a cut at the
	// same number of bytes kept a third of them for a name written in a script
	// that takes three bytes a character. Where the cut feeds a hash, two names
	// differing only past that third folded together.
	const most = 191
	for _, each := range []struct {
		what string
		in   string
		want int
	}{
		{"ASCII shorter than the bound", "libcurl4t64", 11},
		{"ASCII at the bound", strings.Repeat("a", most), most},
		{"ASCII past the bound", strings.Repeat("a", most+10), most},
		{"three bytes a character, at the bound", strings.Repeat("漢", most), most},
		{"three bytes a character, past it", strings.Repeat("漢", most+10), most},
		{"nothing", "", 0},
	} {
		t.Run(each.what, func(t *testing.T) {
			got := bound.HeadRunes(each.in, most)
			if n := utf8.RuneCountInString(got); n != each.want {
				t.Errorf("kept %d characters, want %d", n, each.want)
			}
			if !utf8.ValidString(got) {
				t.Error("the cut landed inside a character")
			}
			if !strings.HasPrefix(each.in, got) {
				t.Error("what came back is not the start of what went in")
			}
		})
	}

	// And two names that differ inside the bound stay different, which is the
	// whole of what a fold key needs.
	one := strings.Repeat("漢", most-1) + "一"
	two := strings.Repeat("漢", most-1) + "二"
	if bound.HeadRunes(one, most) == bound.HeadRunes(two, most) {
		t.Error("two names differing before the bound were cut to the same thing")
	}
}
