// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package markdown

import "strings"

// Literal is a string from somewhere else, written into a markdown document so
// that it reads as the text it is and never as markup.
//
// The server assembles documents that leave the deployment — a release note,
// the issue document — out of strings a third party chose: a component name
// from an SBOM, a description from a feed, a version a scanner reported. Each
// is escaped where it is written, so a package named
// `[Download the fix](https://evil.example/p)` is a name in the document and
// never a link, an image, raw markup or a heading.
//
// A character is escaped where it can open syntax, and left alone where it
// cannot. A release note is also read as source, and `1\.2\.3` for every
// version would make the plain reading wrong to protect a rendering that does
// not need it. DESIGN-text.md § Rendered and escaped text lists what is
// escaped and where.
//
// The first character is judged as though the string began a line, because
// a string written as a list item's content does. Leading spaces are dropped,
// because four of them open a code block where the string begins a line, and
// a renderer shows them as nothing anyway. The last character is judged as
// though the string ended a heading, because the issue document's title is
// one.
func Literal(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		if r < ' ' || r == 0x7f {
			runes[i] = ' '
		}
	}
	for len(runes) > 0 && runes[0] == ' ' {
		runes = runes[1:]
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/8)
	lead, closing := leadingMarker(runes), closingSequence(runes)
	for i, r := range runes {
		if i == lead || i == closing || escaped(runes, i) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// escaped reports whether the character at i can open syntax where it sits.
func escaped(runes []rune, i int) bool {
	before, after := rune(0), rune(0)
	if i > 0 {
		before = runes[i-1]
	}
	if i+1 < len(runes) {
		after = runes[i+1]
	}
	switch runes[i] {
	case '\\', '`', '*', '[', ']', '<', '~', '|':
		return true
	case '_':
		return !wordy(before) || !wordy(after)
	case '&':
		return after == '#' || letter(after)
	case ':':
		return after == '/' && i+2 < len(runes) && runes[i+2] == '/'
	case '.':
		return i >= 3 && strings.EqualFold(string(runes[i-3:i]), "www") &&
			(i == 3 || !wordy(runes[i-4]))
	case '@':
		return wordy(after)
	}
	return false
}

// leadingMarker is the position of a character that would open a block if
// the string began a line, or -1.
func leadingMarker(runes []rune) int {
	i := 0
	for i < len(runes) && runes[i] == ' ' {
		i++
	}
	if i == len(runes) {
		return -1
	}
	// A marker opens a block only when a space or the end of the line follows
	// it, so `6.12.41-1` and `-rc1` stay as they are.
	ends := func(at int) bool { return at >= len(runes) || runes[at] == ' ' }
	switch runes[i] {
	case '>':
		return i
	case '#':
		hashes := i
		for hashes < len(runes) && runes[hashes] == '#' {
			hashes++
		}
		if hashes-i <= 6 && ends(hashes) {
			return i
		}
	case '+':
		if ends(i + 1) {
			return i
		}
	case '-':
		// A run of them is a rule across the page.
		if ends(i+1) || (i+1 < len(runes) && runes[i+1] == '-') {
			return i
		}
	}
	digits := i
	for digits < len(runes) && runes[digits] >= '0' && runes[digits] <= '9' {
		digits++
	}
	if digits > i && digits-i <= 9 && digits < len(runes) &&
		(runes[digits] == '.' || runes[digits] == ')') && ends(digits+1) {
		return digits
	}
	return -1
}

// closingSequence is the position of the first "#" of a run that ends the
// string after a space, or -1. At the end of a heading that run is a closing
// sequence, which a renderer drops.
func closingSequence(runes []rune) int {
	end := len(runes)
	for end > 0 && runes[end-1] == ' ' {
		end--
	}
	start := end
	for start > 0 && runes[start-1] == '#' {
		start--
	}
	if start == end || start == 0 || runes[start-1] != ' ' {
		return -1
	}
	return start
}

func wordy(r rune) bool {
	return letter(r) || (r >= '0' && r <= '9')
}

func letter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
