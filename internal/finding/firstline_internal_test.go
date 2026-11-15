// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A row's summary is the first line or the first sentence, whichever ends
// sooner, and a line longer than 160 characters is cut at the last word
// that fits, counted in characters so a cut never lands inside one.
func TestASummaryIsTheFirstSentenceCutAtAWordWithinTheLimit(t *testing.T) {
	word := strings.Repeat("é", 8)
	words := strings.TrimSpace(strings.Repeat(word+" ", 25))
	for _, c := range []struct {
		name, description, want string
	}{
		{"nothing", "  \n ", ""},
		{"the first line", "Overflow in the parser\nThe second line.", "Overflow in the parser"},
		{"the first sentence", "Overflow in x. Then y.", "Overflow in x."},
		{"a version is not a sentence stop", "fixed in 1.2.3 now", "fixed in 1.2.3 now"},
		{"a long line breaks at the last whole word", words,
			strings.TrimSpace(strings.Repeat(word+" ", 17)) + "…"},
		{"a long line with no space is cut at the limit", strings.Repeat("é", 200),
			strings.Repeat("é", 160) + "…"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := firstLineOf(c.description)
			if got != c.want {
				t.Errorf("firstLineOf(%q) = %q, want %q", c.description, got, c.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("firstLineOf(%q) = %q, which is not valid UTF-8", c.description, got)
			}
		})
	}
}
