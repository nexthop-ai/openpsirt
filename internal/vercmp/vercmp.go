// Package vercmp orders two versions of one package, where the ecosystem it
// came from defines an ordering, and refuses where it does not.
//
// **The refusal is the point.** A comparison that answers confidently for a
// pair it cannot actually order is worse than no comparison, because the answer
// arrives as a recommendation somebody schedules a release around. So callers
// get two results — the comparison, and whether it means anything — and what
// cannot be ordered is shown unranked rather than guessed at.
//
// This is not how a finding is matched to a version: the scanner does that
// before anything here sees it. What this is for is reading the set of versions
// the scanner already named and saying which is furthest along, so that
// "reaching this one also reaches what these earlier releases fixed" can be
// stated rather than left for somebody to work out from a list.
package vercmp

import "strings"

// Scheme is how one ecosystem spells a version.
type Scheme int

const (
	// Unordered is an ecosystem whose versions this does not order. A private
	// module, a vendored fork, and a language runtime naming itself "go1.26.3"
	// all land here, and none of the three is a fault.
	Unordered Scheme = iota
	// Debian is the algorithm dpkg uses: an optional epoch, an upstream
	// version and an optional revision, each compared in alternating runs of
	// non-digits and digits.
	Debian
	// Semantic is dotted numeric parts with an optional pre-release suffix,
	// which is what the language ecosystems publish.
	Semantic
)

// SchemeOf says how an ecosystem spells versions, given the type read out of a
// package identifier.
//
// Taken from the identifier rather than guessed from the version string. Two
// ecosystems spell some versions identically and order them differently, so
// reading the shape of the string would order a package by whichever scheme its
// version happened to resemble.
func SchemeOf(ecosystem string) Scheme {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "deb":
		return Debian
	case "golang", "npm", "cargo":
		return Semantic
	default:
		// Every other ecosystem, including ones that plainly do have an
		// ordering. Adding one is adding its algorithm and the tests that show
		// the algorithm is right; claiming an ordering before that is the
		// confident wrong answer this package exists to refuse.
		return Unordered
	}
}

// Order reports whether a sorts before, with, or after b, and whether the two
// could be ordered at all.
//
// A version the scheme cannot parse leaves the pair unordered even where the
// other half parses cleanly: half an answer about which of two releases is
// further along is not a usable one.
func Order(scheme Scheme, a, b string) (int, bool) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return 0, false
	}
	switch scheme {
	case Debian:
		return debianOrder(a, b), true
	case Semantic:
		return semanticOrder(a, b)
	default:
		return 0, false
	}
}

// Reaches says whether arriving at `candidate` also arrives at `wanted`.
//
// This is the question a picker asks: an issue fixed in an earlier release is
// closed by a later one, so a candidate reaches every version at or before it.
// An unordered pair answers false, which leaves the count to exact matches and
// never overstates what an upgrade would close.
func Reaches(scheme Scheme, candidate, wanted string) bool {
	candidate, wanted = strings.TrimSpace(candidate), strings.TrimSpace(wanted)
	if candidate == wanted {
		return true
	}
	cmp, ok := Order(scheme, wanted, candidate)
	return ok && cmp <= 0
}

// debianOrder compares two Debian versions: epoch, then upstream, then revision.
func debianOrder(a, b string) int {
	ae, au, ar := splitDebian(a)
	be, bu, br := splitDebian(b)
	if c := compareNumeric(ae, be); c != 0 {
		return c
	}
	if c := comparePart(au, bu); c != 0 {
		return c
	}
	return comparePart(ar, br)
}

// splitDebian pulls a version into epoch, upstream version and revision.
//
// The revision is whatever follows the *last* hyphen, because an upstream
// version may contain one and a revision may not.
func splitDebian(v string) (epoch, upstream, revision string) {
	epoch = "0"
	if at := strings.Index(v, ":"); at >= 0 && digits(v[:at]) {
		epoch, v = v[:at], v[at+1:]
	}
	if at := strings.LastIndex(v, "-"); at >= 0 {
		return epoch, v[:at], v[at+1:]
	}
	return epoch, v, ""
}

// comparePart compares one part of a Debian version, alternating runs of
// non-digits and runs of digits until they differ.
func comparePart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// The non-digit run, character by character under the modified order.
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) && !isDigit(a[i]) {
				ac = rank(a[i])
			}
			if j < len(b) && !isDigit(b[j]) {
				bc = rank(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			if i < len(a) && !isDigit(a[i]) {
				i++
			}
			if j < len(b) && !isDigit(b[j]) {
				j++
			}
		}
		// Leading zeros carry no value, so 007 and 7 are one number.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		// The digit run as a number: with the leading zeros gone the longer run
		// is the larger number, and only where both are the same length does
		// the first differing digit decide.
		first := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if first == 0 {
				first = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if first != 0 {
			return sign(first)
		}
	}
	return 0
}

// rank is the order dpkg puts non-digits in: a tilde before everything
// including the end of the string, then letters, then everything else.
//
// The end of a string ranks zero, which is what puts "1.0~rc1" before "1.0"
// and "1.0" before "1.0a".
func rank(c byte) int {
	switch {
	case c == '~':
		return -1
	case isLetter(c):
		return int(c)
	default:
		return int(c) + 256
	}
}

// semanticOrder compares dotted numeric versions, where a pre-release sorts
// before the release it leads to.
func semanticOrder(a, b string) (int, bool) {
	aRel, aPre, aOK := splitSemantic(a)
	bRel, bPre, bOK := splitSemantic(b)
	if !aOK || !bOK {
		return 0, false
	}
	for at := 0; at < len(aRel) || at < len(bRel); at++ {
		// An absent part is zero, so 1.2 and 1.2.0 are one version.
		x, y := "0", "0"
		if at < len(aRel) {
			x = aRel[at]
		}
		if at < len(bRel) {
			y = bRel[at]
		}
		if c := compareNumeric(x, y); c != 0 {
			return c, true
		}
	}
	switch {
	case aPre == "" && bPre == "":
		return 0, true
	case aPre == "":
		// A release is further along than any pre-release of itself.
		return 1, true
	case bPre == "":
		return -1, true
	default:
		return sign(strings.Compare(aPre, bPre)), true
	}
}

// splitSemantic pulls a version into numeric release parts and whatever
// pre-release follows, and says whether it is one this orders at all.
func splitSemantic(v string) (release []string, pre string, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	// Build metadata says nothing about order, so it is dropped rather than
	// compared: "+incompatible" is a note about a module path.
	if at := strings.Index(v, "+"); at >= 0 {
		v = v[:at]
	}
	if at := strings.Index(v, "-"); at >= 0 {
		v, pre = v[:at], v[at+1:]
	}
	if v == "" {
		return nil, "", false
	}
	release = strings.Split(v, ".")
	for _, part := range release {
		if !digits(part) {
			// Anything that is not dotted digits is left unordered rather than
			// guessed at: a runtime calling itself "go1.26.3" and a fork
			// carrying a branch name both arrive here.
			return nil, "", false
		}
	}
	return release, pre, true
}

// compareNumeric compares two runs of digits as numbers without converting
// them, because a version part can be longer than any integer type.
func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return sign(strings.Compare(a, b))
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
