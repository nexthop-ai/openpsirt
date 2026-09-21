package vercmp

import "strings"

// An Alpine version is `digit{.digit}...{letter}{_suffix{number}}...{~hash}{-r number}`,
// and it is read as a run of tokens rather than split on separators. Which
// token may follow which is what decides whether a string is a version at all:
// a letter after a suffix is not a version, and neither is a second letter
// after the first.
//
// Transcribed from Alpine's own reader rather than derived. The suffix
// order, a leading zero turning a number into text, and an unfinished version
// being the greater unless it stops on a pre-release suffix are each a decision
// somebody made. Alpine's own suite is GPL-licensed and is not taken, so the
// cases beside this are written here, one per rule the suite taught.
type apkToken int

// The tokens, in the order a version may hold them. The order is the value:
// where two versions agree as far as one of them goes, the one still going is
// the greater, and that is decided by comparing these.
const (
	apkInitialDigit apkToken = iota
	apkDigit
	apkLetter
	apkSuffix
	apkSuffixNumber
	apkCommitHash
	apkRevision
	apkEnd
	apkInvalid
)

// The suffixes a version may carry, in order. Everything below apkSuffixNone
// leads to a release and everything above follows one, which is the whole
// reason the list is ordered rather than a set.
const (
	apkSuffixInvalid = iota
	apkSuffixAlpha
	apkSuffixBeta
	apkSuffixPre
	apkSuffixRC
	apkSuffixNone
	apkSuffixCVS
	apkSuffixSVN
	apkSuffixGit
	apkSuffixHg
	apkSuffixP
)

// apkSuffixes is what each spelling means. A suffix not in this list makes the
// version invalid rather than sorting somewhere arbitrary.
var apkSuffixes = map[string]int{
	"alpha": apkSuffixAlpha,
	"beta":  apkSuffixBeta,
	"pre":   apkSuffixPre,
	"rc":    apkSuffixRC,
	"cvs":   apkSuffixCVS,
	"svn":   apkSuffixSVN,
	"git":   apkSuffixGit,
	"hg":    apkSuffixHg,
	"p":     apkSuffixP,
}

// apkState is where a reader has got to: the token just read, its text, and
// the two values a comparison may need from it.
type apkState struct {
	token  apkToken
	suffix int
	number string
	value  string
	rest   string
}

// apkOrder compares two Alpine versions token by token.
//
// The refusal is this package's. Alpine compares what it can and falls back to
// sorting the text, which answers for a pair it cannot actually order — and an
// answer like that arrives as a recommendation somebody schedules a release
// around.
func apkOrder(a, b string) (int, bool) {
	if !apkValid(a) || !apkValid(b) {
		return 0, false
	}
	ta, tb := apkFirst(a), apkFirst(b)
	for ta.token == tb.token && ta.token < apkEnd {
		if c := apkCompare(ta, tb); c != 0 {
			return c, true
		}
		ta, tb = apkNext(ta), apkNext(tb)
	}
	switch {
	case ta.token == tb.token:
		return 0, true
	// The leading parts agree and one version keeps going. It is the greater,
	// unless what it goes on to say is that it leads to a release.
	case ta.token == apkSuffix && ta.suffix < apkSuffixNone:
		return -1, true
	case tb.token == apkSuffix && tb.suffix < apkSuffixNone:
		return 1, true
	case ta.token > tb.token:
		return -1, true
	default:
		return 1, true
	}
}

// apkValid reports whether every token reads, which is what makes the string a
// version rather than something shaped like one.
func apkValid(v string) bool {
	state := apkFirst(v)
	for state.token < apkEnd {
		state = apkNext(state)
	}
	return state.token == apkEnd
}

// apkFirst reads the number a version opens with.
func apkFirst(v string) apkState {
	return apkDigits(apkState{token: apkInitialDigit, rest: v})
}

// apkDigits takes the run of digits at the front, which every numeric token is.
func apkDigits(s apkState) apkState {
	at := 0
	for at < len(s.rest) && isDigit(s.rest[at]) {
		at++
	}
	if at == 0 {
		s.token = apkInvalid
		return s
	}
	s.number, s.value, s.rest = s.rest[:at], s.rest[:at], s.rest[at:]
	return s
}

// apkNext reads the token after the one in hand, refusing one the token in
// hand may not be followed by.
func apkNext(s apkState) apkState {
	if s.rest == "" {
		s.token = apkEnd
		return s
	}
	was := s.token
	switch c := s.rest[0]; {
	case c >= 'a' && c <= 'z':
		// One letter, and only straight after the numbers.
		if was > apkDigit {
			s.token = apkInvalid
			return s
		}
		s.value, s.rest = s.rest[:1], s.rest[1:]
		s.token = apkLetter
		return s
	case c == '.':
		if was > apkDigit {
			s.token = apkInvalid
			return s
		}
		s.rest = s.rest[1:]
		s.token = apkDigit
		return apkDigits(s)
	case isDigit(c):
		// A number means a further part where the last token was a number, and
		// the count on a suffix where it was a suffix. Anywhere else it is not
		// a version.
		switch was {
		case apkInitialDigit, apkDigit:
			s.token = apkDigit
		case apkSuffix:
			s.token = apkSuffixNumber
		default:
			s.token = apkInvalid
			return s
		}
		return apkDigits(s)
	case c == '_':
		if was > apkSuffixNumber {
			s.token = apkInvalid
			return s
		}
		s.rest = s.rest[1:]
		at := 0
		for at < len(s.rest) && isLetter(s.rest[at]) {
			at++
		}
		s.value, s.rest = s.rest[:at], s.rest[at:]
		suffix, known := apkSuffixes[s.value]
		if !known {
			s.token = apkInvalid
			return s
		}
		s.suffix, s.token = suffix, apkSuffix
		return s
	case c == '~':
		if was >= apkCommitHash {
			s.token = apkInvalid
			return s
		}
		s.rest = s.rest[1:]
		at := 0
		for at < len(s.rest) && isHex(s.rest[at]) {
			at++
		}
		if at == 0 {
			s.token = apkInvalid
			return s
		}
		s.value, s.rest = s.rest[:at], s.rest[at:]
		s.token = apkCommitHash
		return s
	case c == '-':
		if was >= apkRevision {
			s.token = apkInvalid
			return s
		}
		if !strings.HasPrefix(s.rest, "-r") {
			s.token = apkInvalid
			return s
		}
		s.rest = s.rest[2:]
		s.token = apkRevision
		return apkDigits(s)
	default:
		s.token = apkInvalid
		return s
	}
}

// apkCompare compares two tokens of the same kind.
func apkCompare(a, b apkState) int {
	switch a.token {
	case apkDigit:
		// A leading zero makes the part a fraction rather than a number, so
		// "8.2.0015" is below "8.2.002". Compared as numbers they would be the
		// other way round.
		if strings.HasPrefix(a.value, "0") || strings.HasPrefix(b.value, "0") {
			return sign(strings.Compare(a.value, b.value))
		}
		return compareNumeric(a.number, b.number)
	case apkInitialDigit, apkSuffixNumber, apkRevision:
		return compareNumeric(a.number, b.number)
	case apkLetter:
		return sign(strings.Compare(a.value, b.value))
	case apkSuffix:
		return sign(a.suffix - b.suffix)
	default:
		return sign(strings.Compare(a.value, b.value))
	}
}

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
