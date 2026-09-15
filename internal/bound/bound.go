// Package bound cuts a string to a number of bytes without splitting a
// character.
//
// A cut at a byte offset lands inside a multi-byte character about two times
// in three, and what is left is not valid UTF-8. PostgreSQL refuses such a
// value outright and MySQL and MariaDB refuse it in strict mode, so the write
// that was recording why something failed fails in turn — leaving no record
// of either failure. SQLite stores it happily, which is the engine the quick
// test loop uses, so nothing local sees it.
//
// It is one package because it was five: every bound in this tree was written
// by hand at its call site, each spelling the same slice, and the two that
// were written correctly are the two whose authors had already been bitten.
// The direction is the part that differs and the part that is easy to get
// wrong — a cut from the end leaves the partial character at the front — so
// both directions are here and neither is open-coded again.
package bound

import "unicode/utf8"

// Head keeps the first most bytes, cut on a character boundary.
//
// The partial character is at the end, so the trim goes backward.
func Head(s string, most int) string {
	if most <= 0 {
		return ""
	}
	if len(s) <= most {
		return s
	}
	cut := s[:most]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
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
