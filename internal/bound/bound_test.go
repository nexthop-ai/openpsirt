// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package bound

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestACutInsideACharacterLeavesValidText(t *testing.T) {
	// The euro sign is three bytes, so a bound that is not a multiple of
	// three falls inside one. What survives is valid text, so it is stored as
	// it is rather than with a replacement character where the cut fell.
	text := strings.Repeat("€", 10)
	for most := 1; most <= len(text); most++ {
		head := Head(text, most)
		if !utf8.ValidString(head) {
			t.Fatalf("Head(%d) is not valid UTF-8: %q", most, head)
		}
		if len(head) > most {
			t.Fatalf("Head(%d) kept %d bytes", most, len(head))
		}
		if !strings.HasPrefix(text, head) {
			t.Fatalf("Head(%d) is not a prefix: %q", most, head)
		}
		tail := Tail(text, most)
		if !utf8.ValidString(tail) {
			t.Fatalf("Tail(%d) is not valid UTF-8: %q", most, tail)
		}
		if len(tail) > most {
			t.Fatalf("Tail(%d) kept %d bytes", most, len(tail))
		}
		if !strings.HasSuffix(text, tail) {
			t.Fatalf("Tail(%d) is not a suffix: %q", most, tail)
		}
	}
}

func TestNothingIsCutFromAStringThatAlreadyFits(t *testing.T) {
	for _, text := range []string{"", "short", "€€"} {
		if got := Head(text, 16); got != text {
			t.Fatalf("Head(%q) = %q", text, got)
		}
		if got := Tail(text, 16); got != text {
			t.Fatalf("Tail(%q) = %q", text, got)
		}
	}
}

func TestTheDirectionsKeepOppositeEnds(t *testing.T) {
	if got := Head("abcdef", 3); got != "abc" {
		t.Fatalf("Head = %q", got)
	}
	if got := Tail("abcdef", 3); got != "def" {
		t.Fatalf("Tail = %q", got)
	}
}

// A tail of bytes that begin no character loses at most the three a split
// character can leave, rather than everything up to the first that does.
func TestATailOfBinaryOutputIsNotTrimmedAway(t *testing.T) {
	noise := strings.Repeat("\x80", 10) + "abc"
	if got := Tail(noise, 12); got != noise[len(noise)-12+3:] {
		t.Fatalf("the tail of binary output came back as %q", got)
	}
	if got := Tail(strings.Repeat("\x80", 20), 10); len(got) != 7 {
		t.Fatalf("a tail of nothing but continuation bytes came back as %q", got)
	}
}

func TestABoundOfNoneKeepsNothing(t *testing.T) {
	// A caller computing a bound from a setting can arrive at zero, and a
	// negative slice index is a panic rather than an empty string.
	if got := Head("abc", 0); got != "" {
		t.Fatalf("Head = %q", got)
	}
	if got := Tail("abc", -1); got != "" {
		t.Fatalf("Tail = %q", got)
	}
}

func TestABadByteEarlyOnDoesNotSwallowWhatFollowsIt(t *testing.T) {
	// The text cut is often a program's own output, and a scanner that fails
	// writes whatever it likes to standard error. The cut is about the last
	// character, not about the string, so a bad byte before it does not move
	// it.
	noise := "\xff" + strings.Repeat("a", 100)
	if got := Head(noise, 50); got != noise[:50] {
		t.Fatalf("a bad byte at the front cut the message to %q", got)
	}

	// And the character the bound falls inside is still the one cut: the
	// trim goes back at most the three bytes a split character can leave.
	split := "\xff" + strings.Repeat("a", 47) + "€"
	if got := Head(split, 50); got != split[:48] {
		t.Fatalf("the split character was not cut: %q", got)
	}
}

func TestACutInsideAFourByteCharacterLeavesValidText(t *testing.T) {
	// A four-byte character leaves three of its bytes behind a cut, which
	// is the furthest the trim goes back.
	text := strings.Repeat("😀", 10)
	for most := 1; most <= len(text); most++ {
		head := Head(text, most)
		if !utf8.ValidString(head) || len(head) != most/4*4 {
			t.Fatalf("Head(%d) = %q", most, head)
		}
		tail := Tail(text, most)
		if !utf8.ValidString(tail) || len(tail) != most/4*4 {
			t.Fatalf("Tail(%d) = %q", most, tail)
		}
	}
}

func TestACharacterBoundOfNoneKeepsNothing(t *testing.T) {
	if got := HeadRunes("abc", 0); got != "" {
		t.Fatalf("HeadRunes = %q", got)
	}
	if got := HeadRunes("abc", -1); got != "" {
		t.Fatalf("HeadRunes = %q", got)
	}
}
