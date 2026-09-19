// Package bound cuts a string to a number of bytes without splitting a
// character.
//
// A cut at a byte offset lands inside a multi-byte character about two times
// in three, and what is left is not valid UTF-8. PostgreSQL refuses such a
// value outright and MySQL and MariaDB refuse it in strict mode, so a write
// recording why something failed fails in turn, leaving no record of either
// failure. SQLite stores it happily, and SQLite is the engine the quick test
// loop uses, so nothing local sees it.
//
// One package, because a bound written by hand at each call site is the same
// slice spelled again by somebody who has not been bitten yet. The direction
// is the part that differs and the part that is easy to get wrong — a cut from
// the end leaves the partial character at the front — so both are here and
// neither is open-coded again.
package bound

import "unicode/utf8"

// Head keeps the first most bytes, cut on a character boundary.
//
// The partial character is at the end, so the trim goes backward, and only as
// far as the last character can begin, which is three bytes. The text being
// cut is often a program's own output, which nobody promised was text at all:
// asked instead whether the whole kept prefix decodes, one bad byte anywhere
// in it throws away everything after that byte, so a message quoting a failed
// scan's standard error comes back cut to whatever preceded its first piece of
// binary. That question also re-reads the whole prefix on every step, which on
// a megabyte of output is a megabyte re-read per byte trimmed.
//
// Validity of the whole is not on offer: a bad byte before the bound is kept,
// and a string shorter than the bound is handed back as it came. What is
// promised is the cut.
func Head(s string, most int) string {
	if most <= 0 {
		return ""
	}
	if len(s) <= most {
		return s
	}
	cut := s[:most]
	// A character that the cut split keeps at most three of its bytes, so a
	// start further back than that is a start the cut did not split.
	for i := len(cut) - 1; i >= 0 && len(cut)-i < utf8.UTFMax; i-- {
		if !utf8.RuneStart(cut[i]) {
			continue
		}
		// The last character begins here. It is whole if what follows it is
		// all the bytes it takes, and the decode says so.
		if r, size := utf8.DecodeRuneInString(cut[i:]); r != utf8.RuneError || size > 1 {
			return cut
		}
		return cut[:i]
	}
	return cut
}

// Tail keeps the last most bytes, cut on a character boundary.
//
// The partial character is at the front, so the trim goes forward.
func Tail(s string, most int) string {
	if most <= 0 {
		return ""
	}
	if len(s) <= most {
		return s
	}
	cut := s[len(s)-most:]
	for len(cut) > 0 && !utf8.RuneStart(cut[0]) {
		cut = cut[1:]
	}
	return cut
}

// HeadRunes keeps the first most characters.
//
// For a bound that is a number of characters rather than a number of bytes,
// which is what every indexed name column in this schema is declared in:
// PostgreSQL, MySQL and MariaDB all count a VARCHAR's length in characters.
// Cut at the same number of bytes, a name written in a script that takes three
// bytes a character was cut to a third of what the column holds — and where
// the cut feeds a hash, two names differing only past that third folded
// together.
//
// It is not the same function as Head with a bigger number. The two answer
// different questions, and a caller bounding bytes — a message, a program's
// output, anything going into a column declared in bytes — wants Head.
func HeadRunes(s string, most int) string {
	if most <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= most {
		return s
	}
	kept := 0
	for i := range s {
		if kept == most {
			return s[:i]
		}
		kept++
	}
	return s
}
