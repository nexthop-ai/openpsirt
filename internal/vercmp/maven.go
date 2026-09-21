package vercmp

import (
	"strconv"
	"strings"
)

// mavenKind is what one item of a version is: a number, a word, or a level
// holding more items.
type mavenKind int

const (
	mavenNumber mavenKind = iota
	mavenWord
	mavenLevel
)

// mavenItem is one item of a version, and the level it may hold.
type mavenItem struct {
	kind   mavenKind
	number string
	word   string
	items  []*mavenItem
}

// The words Maven knows, in order. Everything before the empty string leads to
// a release and everything after follows one, which is the whole reason the
// list is ordered rather than a set. A word not in it sorts above all of them.
var mavenWords = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

// What each spelling means. A version saying it is generally available, final
// or released is saying it is the release, and a change request is a release
// candidate.
var mavenAliases = map[string]string{
	"ga":      "",
	"final":   "",
	"release": "",
	"cr":      "rc",
}

// mavenRelease is where the release itself sits among the words, which is what
// a word is compared against to decide whether it leads to a release or
// follows one.
var mavenRelease = mavenRank("")

// mavenOrder compares two Maven versions, which are trees rather than lists.
// A hyphen opens a nested level, and so does the boundary between a run of
// digits and a run of letters, which is why "1.0.0.rc1" and "1.0.0-rc2" are
// comparable at all and why the first is the lesser.
//
// Transcribed from the implementation that defines it. Nothing about the shape
// is derivable from a description of Maven versions: that a word this has
// never heard of sorts above every one it knows, that a trailing zero, a
// trailing release word and a trailing empty level are each removed before any
// comparison, and that a level compared against nothing asks each of its own
// items the same question — each is a decision somebody made, and the project's
// own suite is what says whether a reading of them is right.
//
// The refusal is this package's and not Maven's. Maven orders any two strings,
// so a word an advisory wrote where a version belongs sorts somewhere definite
// and the upgrade planner recommends moving to it. Maven states no rule for
// what a version is, so the rule applied here is the one the distribution
// schemes use: it begins with a digit and holds only the characters a version
// may hold.
func mavenOrder(a, b string) (int, bool) {
	if !mavenIsVersion(a) || !mavenIsVersion(b) {
		return 0, false
	}
	return mavenCompare(mavenRead(a), mavenRead(b)), true
}

// mavenIsVersion says whether a string is one this orders.
func mavenIsVersion(v string) bool {
	if v == "" || !isDigit(v[0]) {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case isDigit(c), isLetter(c):
		case c == '.', c == '-', c == '_', c == '+':
		default:
			return false
		}
	}
	return true
}

// mavenRead pulls a version into its tree of items.
//
// Three things open a new level: a hyphen, a run of digits that follows a run
// of letters, and a run of letters that follows a run of digits. The last two
// are why a separator between a number and a word is optional — "1.0a" and
// "1.0-a" are one version.
func mavenRead(v string) *mavenItem {
	v = strings.ToLower(v)

	root := &mavenItem{kind: mavenLevel}
	level := root
	opened := []*mavenItem{root}
	open := func() {
		deeper := &mavenItem{kind: mavenLevel}
		level.items = append(level.items, deeper)
		level = deeper
		opened = append(opened, deeper)
	}

	inDigits, start := false, 0
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '.' || c == '-':
			// A separator with nothing before it stands for a zero, so "1..2"
			// and "1.0.2" are one version.
			if i == start {
				level.items = append(level.items, &mavenItem{kind: mavenNumber, number: "0"})
			} else {
				level.items = append(level.items, mavenOne(inDigits, v[start:i]))
			}
			start = i + 1
			if c == '-' {
				open()
			}
		case isDigit(c):
			if !inDigits && i > start {
				if len(level.items) > 0 {
					open()
				}
				level.items = append(level.items, mavenWordItem(v[start:i], true))
				start = i
				open()
			}
			inDigits = true
		default:
			if inDigits && i > start {
				level.items = append(level.items, mavenOne(true, v[start:i]))
				start = i
				open()
			}
			inDigits = false
		}
	}
	if len(v) > start {
		if !inDigits && len(level.items) > 0 {
			open()
		}
		level.items = append(level.items, mavenOne(inDigits, v[start:]))
	}

	// Innermost first, because emptying a level is what makes the level above
	// it able to drop it.
	for at := len(opened) - 1; at >= 0; at-- {
		opened[at].trim()
	}
	return root
}

// mavenOne is one item read from a run of characters.
func mavenOne(inDigits bool, text string) *mavenItem {
	if inDigits {
		trimmed := strings.TrimLeft(text, "0")
		if trimmed == "" {
			trimmed = "0"
		}
		return &mavenItem{kind: mavenNumber, number: trimmed}
	}
	return mavenWordItem(text, false)
}

// mavenWordItem is one word, under the name Maven knows it by.
//
// A single letter with a number after it is the short spelling of a word:
// "1a1" is the first alpha. Without the number it is a word of its own, which
// is why "1a" is not.
func mavenWordItem(word string, beforeNumber bool) *mavenItem {
	if beforeNumber && len(word) == 1 {
		switch word {
		case "a":
			word = "alpha"
		case "b":
			word = "beta"
		case "m":
			word = "milestone"
		}
	}
	if alias, known := mavenAliases[word]; known {
		word = alias
	}
	return &mavenItem{kind: mavenWord, word: word}
}

// trim drops what a level says nothing by holding: a zero, the release word,
// and a level that has been emptied. It stops at the first number or word that
// does say something, and keeps looking past a level that does.
//
// This is what makes "1", "1.0", "1.0.0", "1-0" and "1.ga" one version.
func (m *mavenItem) trim() {
	for at := len(m.items) - 1; at >= 0; at-- {
		last := m.items[at]
		if last.silent() {
			m.items = append(m.items[:at], m.items[at+1:]...)
		} else if last.kind != mavenLevel {
			break
		}
	}
}

// silent says whether an item carries nothing, which is what lets it be
// dropped from the end of the level holding it.
func (m *mavenItem) silent() bool {
	switch m.kind {
	case mavenNumber:
		return strings.Trim(m.number, "0") == ""
	case mavenWord:
		return mavenRank(m.word) == mavenRelease
	default:
		return len(m.items) == 0
	}
}

// mavenRank is a word's place in the order, as something two of them can be
// compared by.
//
// A string rather than a number, because a word Maven has never heard of has
// no place in the list and takes the one after it, and comparing "6-ubuntu"
// against "3" as text puts every unknown word above every known one without a
// second rule saying so.
func mavenRank(word string) string {
	for at, known := range mavenWords {
		if word == known {
			return strconv.Itoa(at)
		}
	}
	return strconv.Itoa(len(mavenWords)) + "-" + word
}

// mavenCompare compares two items, where b may be absent.
//
// This is not a total order, and a sort over a set holding a triple that shows
// it is stable rather than ordered. A level compared against a version that
// ran out answers by its own contents, while a zero answers that it is equal
// and reveals the word behind it a position later, so "1" is below "1-1",
// "1-1" is below "1.0.alpha.1", and "1" is above "1.0.alpha.1" — all three at
// once. Maven's own comparison does the same and this is transcribed from it.
//
// A level nests inside the level that opened it, so the depth is the number of
// hyphens and the structure is proportional to the input. What keeps that from
// being a way to spend the container's memory is the bound on how long a
// version may be, which every scheme is held to.
//
// Absent is not the same as empty. A version that has run out is compared
// against what the other one still holds, and what that holds decides which is
// the greater: a number above zero or a word following the release makes the
// longer version the greater, and a word leading to a release makes it the
// lesser.
func mavenCompare(a, b *mavenItem) int {
	switch a.kind {
	case mavenNumber:
		if b == nil {
			if strings.Trim(a.number, "0") == "" {
				return 0
			}
			return 1
		}
		if b.kind == mavenNumber {
			return compareNumeric(a.number, b.number)
		}
		// A number outranks a word and the level a hyphen opens, which is what
		// puts "1.1" above "1-sp" and above "1-1".
		return 1
	case mavenWord:
		if b == nil {
			return sign(strings.Compare(mavenRank(a.word), mavenRelease))
		}
		switch b.kind {
		case mavenWord:
			return sign(strings.Compare(mavenRank(a.word), mavenRank(b.word)))
		case mavenNumber:
			return -1
		default:
			return -1
		}
	default:
		if b == nil {
			// Every item, not only the first: a level holding a word that
			// leads to a release is below the version that stopped, however
			// many zeros stand in front of it.
			for _, each := range a.items {
				if c := mavenCompare(each, nil); c != 0 {
					return c
				}
			}
			return 0
		}
		switch b.kind {
		case mavenNumber:
			return -1
		case mavenWord:
			return 1
		default:
			return mavenLevels(a.items, b.items)
		}
	}
}

// mavenLevels compares two levels item by item, asking whichever one still has
// an item how it compares against nothing.
func mavenLevels(a, b []*mavenItem) int {
	for at := 0; at < len(a) || at < len(b); at++ {
		var left, right *mavenItem
		if at < len(a) {
			left = a[at]
		}
		if at < len(b) {
			right = b[at]
		}
		c := 0
		switch {
		case left != nil:
			c = mavenCompare(left, right)
		case right != nil:
			c = -mavenCompare(right, left)
		}
		if c != 0 {
			return c
		}
	}
	return 0
}
