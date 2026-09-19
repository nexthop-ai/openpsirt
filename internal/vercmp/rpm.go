package vercmp

import "strings"

// rpmOrder compares two RPM versions: epoch, then version, then release.
//
// **Transcribed from rpmvercmp rather than derived.** The algorithm is not
// something to reason out from a description — the tilde and caret rules, a
// numeric run outranking an alphabetic one, and separators being skipped
// wholesale are each a decision somebody made, and the published test vectors
// are what say whether a reading of them is right. `testdata/rpmvercmp.at` is
// that suite, taken from the project's own tests.
//
// The refusal is this package's and not rpm's. rpm orders any two strings,
// which reads as a scheme that never fails: an advisory stating its fixed
// version as a word would sort somewhere definite and the upgrade planner would
// recommend moving to it.
func rpmOrder(a, b string) (int, bool) {
	ae, av, ar, aOK := splitRPM(a)
	be, bv, br, bOK := splitRPM(b)
	if !aOK || !bOK {
		return 0, false
	}
	if c := compareNumeric(ae, be); c != 0 {
		return c, true
	}
	if c := rpmSegment(av, bv); c != 0 {
		return c, true
	}
	return rpmSegment(ar, br), true
}

// splitRPM pulls a version into epoch, version and release, and says whether
// what it was given is a version at all.
//
// The release is whatever follows the last hyphen. A hyphen is not a character
// a version may hold, so a string carrying a second one is refused either way
// and where the cut is made changes no accepted answer.
//
// What makes a string not a version here is the same test the Debian
// reader applies, for the same reason: the version part begins with a digit and
// every part is drawn from the characters a version may hold. A word an
// advisory wrote where a version belongs fails both.
func splitRPM(v string) (epoch, version, release string, ok bool) {
	epoch = "0"
	if at := strings.Index(v, ":"); at >= 0 {
		if !digits(v[:at]) {
			return "", "", "", false
		}
		epoch, v = v[:at], v[at+1:]
	}
	if at := strings.LastIndex(v, "-"); at >= 0 {
		version, release = v[:at], v[at+1:]
	} else {
		version = v
	}
	if version == "" || !isDigit(version[0]) {
		return "", "", "", false
	}
	if !rpmCharacters(version) || !rpmCharacters(release) {
		return "", "", "", false
	}
	return epoch, version, release, true
}

// rpmCharacters says whether every character is one an RPM version may hold.
//
// The hyphen is not among them: it separates the release, and the caller has
// already cut at the last one. Bytes above ASCII are refused here even though
// the comparison below would treat them as separators — a version this cannot
// read is one to leave unordered rather than one to order by ignoring part of
// it.
func rpmCharacters(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c == '.', c == '_', c == '+', c == '~', c == '^':
		default:
			return false
		}
	}
	return true
}

// rpmSegment compares one segment — the version or the release — the way
// rpmvercmp does.
//
// Anything that is not alphanumeric, a tilde or a caret is a separator and is
// skipped, so "1.2" and "1_2" and "1..2" are one version. What is left is
// compared in runs: a run of digits against a run of digits as numbers, a run
// of letters against a run of letters as text, and a digit run against a letter
// run as the newer of the two.
func rpmSegment(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !rpmSignificant(a[i]) {
			i++
		}
		for j < len(b) && !rpmSignificant(b[j]) {
			j++
		}

		// A tilde sorts before everything, including the end of the string,
		// which is what puts a pre-release before the release it leads to.
		if at(a, i) == '~' || at(b, j) == '~' {
			if at(a, i) != '~' {
				return 1
			}
			if at(b, j) != '~' {
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		// A caret is the same idea the other way up: it sorts after the end of
		// the string and before anything that follows it, which is what a
		// snapshot taken after a release is spelled with.
		if at(a, i) == '^' || at(b, j) == '^' {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case at(a, i) != '^':
				return 1
			case at(b, j) != '^':
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		// One of them has run out. Which one decides the answer below, after
		// the loop, because a string with something left over is the greater.
		if i >= len(a) || j >= len(b) {
			break
		}

		start, other := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isLetter(a[i]) {
				i++
			}
			for j < len(b) && isLetter(b[j]) {
				j++
			}
		}
		one, two := a[start:i], b[other:j]
		// The runs are of different kinds, so one of them is empty. A numeric
		// run is newer than an alphabetic one, which is rpm's own rule and the
		// reason "1.2" is newer than "1.a".
		if two == "" {
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			one, two = strings.TrimLeft(one, "0"), strings.TrimLeft(two, "0")
			if len(one) != len(two) {
				return sign(len(one) - len(two))
			}
		}
		if c := strings.Compare(one, two); c != 0 {
			return sign(c)
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

// rpmSignificant says whether a byte takes part in the comparison at all.
// Everything else separates one run from the next.
func rpmSignificant(c byte) bool {
	return isDigit(c) || isLetter(c) || c == '~' || c == '^'
}

// at is the byte at an index, or zero past the end, so the rules above can ask
// about a position that may not exist.
func at(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}
