package vercmp

import "strings"

// nugetVersion is one NuGet version as its comparison reads it: four numbers,
// and the release labels that follow a hyphen. Build metadata after a plus is
// checked and then dropped, because it says nothing about order.
type nugetVersion struct {
	numbers [4]int64
	labels  []string
}

// nugetMost is the largest a number in a NuGet version may be. The reference
// holds each in a 32-bit integer and refuses a version whose number does not
// fit, rather than reading it as some other number.
const nugetMost = 1<<31 - 1

// nugetOrder compares two NuGet versions.
//
// Transcribed from NuGet's own parser and comparer rather than read as
// Semantic Versioning, which it resembles and is not. A fourth number is
// permitted and compared. A missing number is zero, so "1.0" and "1.0.0.0" are
// one version. Release labels compare without regard to case, and a label is
// a number only where it fits the reference's 32-bit integer, so a longer run
// of digits compares as text.
//
// A string the reference would refuse to parse is refused here. Its own suite
// is what says which those are.
func nugetOrder(a, b string) (int, bool) {
	x, xOK := nugetRead(a)
	y, yOK := nugetRead(b)
	if !xOK || !yOK {
		return 0, false
	}
	for at := range x.numbers {
		if c := sign64(x.numbers[at] - y.numbers[at]); c != 0 {
			return c, true
		}
	}
	switch {
	case len(x.labels) == 0 && len(y.labels) == 0:
		return 0, true
	case len(x.labels) == 0:
		// A release is further along than any pre-release of itself.
		return 1, true
	case len(y.labels) == 0:
		return -1, true
	}
	for at := 0; at < len(x.labels) || at < len(y.labels); at++ {
		switch {
		case at >= len(x.labels):
			return -1, true
		case at >= len(y.labels):
			return 1, true
		}
		if c := nugetLabel(x.labels[at], y.labels[at]); c != 0 {
			return c, true
		}
	}
	return 0, true
}

// nugetRead pulls a version into its numbers and labels, and says whether it
// is one NuGet would parse.
//
// The version runs to the first hyphen or plus. The labels run from that
// hyphen to the first plus after it, and a hyphen inside them is part of a
// label. Everything after the plus is metadata.
func nugetRead(v string) (nugetVersion, bool) {
	var out nugetVersion
	numbers, rest := v, ""
	if at := strings.IndexAny(v, "-+"); at >= 0 {
		numbers, rest = v[:at], v[at:]
	}
	if !nugetNumbers(numbers, &out.numbers) {
		return nugetVersion{}, false
	}
	if strings.HasPrefix(rest, "-") {
		labels := rest[1:]
		if at := strings.IndexByte(labels, '+'); at >= 0 {
			labels, rest = labels[:at], labels[at:]
		} else {
			rest = ""
		}
		out.labels = strings.Split(labels, ".")
		for _, label := range out.labels {
			if !nugetPart(label, false) {
				return nugetVersion{}, false
			}
		}
	}
	if strings.HasPrefix(rest, "+") {
		for _, part := range strings.Split(rest[1:], ".") {
			if !nugetPart(part, true) {
				return nugetVersion{}, false
			}
		}
	}
	return out, true
}

// nugetNumbers reads between one and four dotted numbers.
//
// Whitespace around a number is allowed and whitespace inside one is not,
// which is the reference's rule: "19 . 19" is a version and "1 9" is not. A
// dot must be followed by a number, so "1." and "1..2" are refused, and a
// number past what a 32-bit integer holds is refused rather than wrapped.
func nugetNumbers(s string, into *[4]int64) bool {
	at, part := 0, 0
	for {
		if part == len(into) {
			return false
		}
		for at < len(s) && nugetSpace(s[at]) {
			at++
		}
		start := at
		var n int64
		for at < len(s) && isDigit(s[at]) {
			n = n*10 + int64(s[at]-'0')
			if n > nugetMost {
				return false
			}
			at++
		}
		if at == start {
			return false
		}
		into[part] = n
		part++
		for at < len(s) && nugetSpace(s[at]) {
			at++
		}
		if at == len(s) {
			return true
		}
		if s[at] != '.' || at == len(s)-1 {
			return false
		}
		at++
	}
}

// nugetPart says whether one dotted part of the labels or the metadata is one
// the reference accepts: not empty, only letters, digits and hyphens, and —
// among the labels — no leading zero on a part that is all digits.
func nugetPart(s string, leadingZeros bool) bool {
	if s == "" {
		return false
	}
	if !leadingZeros && len(s) > 1 && s[0] == '0' && digits(s[1:]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isDigit(c) && !isLetter(c) && c != '-' {
			return false
		}
	}
	return true
}

// nugetLabel compares two release labels: numerically where both are
// numbers, a number below a word, and two words without regard to case.
func nugetLabel(a, b string) int {
	x, xNumber := nugetLabelNumber(a)
	y, yNumber := nugetLabelNumber(b)
	switch {
	case xNumber && yNumber:
		return sign64(x - y)
	case xNumber:
		return -1
	case yNumber:
		return 1
	default:
		return sign(strings.Compare(strings.ToUpper(a), strings.ToUpper(b)))
	}
}

// nugetLabelNumber reads a label as the reference does: a number is an
// optional minus sign and digits whose value fits a 32-bit integer. "-1" is a
// valid label, so the sign is reachable.
func nugetLabelNumber(s string) (int64, bool) {
	negative := strings.HasPrefix(s, "-")
	body := strings.TrimPrefix(s, "-")
	if !digits(body) {
		return 0, false
	}
	var n int64
	for i := 0; i < len(body); i++ {
		n = n*10 + int64(body[i]-'0')
		if n > nugetMost+1 {
			return 0, false
		}
	}
	if negative {
		n = -n
	}
	if n > nugetMost {
		return 0, false
	}
	return n, true
}

// nugetSpace is the whitespace allowed around a number. ASCII alone: a byte
// read as a character on its own is not a character, and a stray byte that
// happens to be a space's code point is not a space.
func nugetSpace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}

func sign64(n int64) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
