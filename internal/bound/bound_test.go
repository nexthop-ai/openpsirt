package bound

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestACutInsideACharacterLeavesValidText(t *testing.T) {
	// The euro sign is three bytes, so a bound that is not a multiple of
	// three falls inside one. What survives has to be something an engine
	// will store: PostgreSQL refuses invalid UTF-8 and so do MySQL and
	// MariaDB in strict mode.
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
	// What is cut is often a program's own output, and a scanner that fails
	// writes whatever it likes to standard error. Asked whether the whole
	// kept prefix decodes, the trim walked back past every good character to
	// the first bad byte and threw away the rest — so the recorded reason for
	// a failed scan was whatever preceded the binary, which is usually
	// nothing. The cut is about the last character, not about the string.
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
