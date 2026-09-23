// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vercmp

import (
	"regexp"
	"strings"
)

// PEP 440 is defined by a regular expression, so the reader is that expression
// rather than a hand-rolled walk of the string. The other schemes here are
// transcribed from an implementation because their ecosystems define them that
// way; this one is transcribed from the specification because its ecosystem
// does.
//
// Written without the case-insensitive flag the specification's own copy
// carries. The input is lowered first, which is the same answer for ASCII and
// a narrower one above it: a local segment holding a capital letter whose
// lowering is not a letter is refused rather than matched.
var pypiVersionPattern = regexp.MustCompile(
	`^v?` +
		`(?:(?P<epoch>[0-9]+)!)?` +
		`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
		`(?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?` +
		`(?:(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?` +
		`(?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?` +
		`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`,
)

// Where a pre-release sits against the release it leads to. A version whose
// only suffix is a development one sits below every pre-release, which is what
// separates the two kinds of unfinished: a development build of the release
// precedes its first alpha, and one of the alpha precedes the alpha itself.
const (
	pypiPreDevOnly = -1
	pypiPreAlpha   = 0
	pypiPreBeta    = 1
	pypiPreRC      = 2
	pypiPreNone    = 3
)

// The spellings a pre-release letter may arrive in, and what each one means.
// One release candidate written four ways is one release candidate.
var pypiPreRanks = map[string]int{
	"alpha":   pypiPreAlpha,
	"a":       pypiPreAlpha,
	"beta":    pypiPreBeta,
	"b":       pypiPreBeta,
	"c":       pypiPreRC,
	"pre":     pypiPreRC,
	"preview": pypiPreRC,
	"rc":      pypiPreRC,
}

// pypiVersion is a version broken into the parts that order it.
//
// The numbers stay as the digits they arrived as rather than becoming an
// integer type. A release segment has no bound on its length, and a version
// too long for an integer is a version to order rather than one to overflow.
type pypiVersion struct {
	epoch    string
	release  []string
	preRank  int
	preN     string
	postRank int
	postN    string
	devRank  int
	devN     string
	local    []pypiLocalPart
	hasLocal bool
}

// pypiLocalPart is one segment of what follows a plus sign. A segment of
// digits is a number and everything else is text, and the two do not order
// against each other by their contents.
type pypiLocalPart struct {
	numeric bool
	text    string
}

// pypiOrder compares two versions the way PEP 440 orders them.
//
// The refusal is the specification's own. Unlike the distribution schemes,
// which order any two strings and need a rule invented for them, this grammar
// already says what a version is: a word an advisory wrote where a version
// belongs does not match it, and nothing further is needed to turn it away.
func pypiOrder(a, b string) (int, bool) {
	left, aOK := pypiRead(a)
	right, bOK := pypiRead(b)
	if !aOK || !bOK {
		return 0, false
	}

	if c := compareNumeric(left.epoch, right.epoch); c != 0 {
		return c, true
	}
	if c := pypiRelease(left.release, right.release); c != 0 {
		return c, true
	}
	// Pre-release, post-release and development, each as where it sits and
	// then as what number it carries. Compared in this order and not
	// separately: a post-release of an alpha is still an alpha.
	if c := sign(left.preRank - right.preRank); c != 0 {
		return c, true
	}
	if c := compareNumeric(left.preN, right.preN); c != 0 {
		return c, true
	}
	if c := sign(left.postRank - right.postRank); c != 0 {
		return c, true
	}
	if c := compareNumeric(left.postN, right.postN); c != 0 {
		return c, true
	}
	if c := sign(left.devRank - right.devRank); c != 0 {
		return c, true
	}
	if c := compareNumeric(left.devN, right.devN); c != 0 {
		return c, true
	}
	return pypiLocal(left, right), true
}

// pypiRelease compares two release segments.
//
// Trailing zeros are gone by the time this is reached, so the shorter of two
// segments that agree as far as it goes is the earlier version: "1" against
// "1.0.1" is a prefix rather than a pair of equal-length numbers.
func pypiRelease(a, b []string) int {
	for at := 0; at < len(a) && at < len(b); at++ {
		if c := compareNumeric(a[at], b[at]); c != 0 {
			return c
		}
	}
	return sign(len(a) - len(b))
}

// pypiLocal compares what follows a plus sign.
//
// A version carrying one is above the same version without, which is what puts
// a distribution's rebuild above what it was built from. Within a local
// version, text sorts below a number and the shorter of two matching runs
// sorts below the longer.
func pypiLocal(a, b pypiVersion) int {
	if a.hasLocal != b.hasLocal {
		if a.hasLocal {
			return 1
		}
		return -1
	}
	for at := 0; at < len(a.local) && at < len(b.local); at++ {
		one, two := a.local[at], b.local[at]
		switch {
		case one.numeric != two.numeric:
			if one.numeric {
				return 1
			}
			return -1
		case one.numeric:
			if c := compareNumeric(one.text, two.text); c != 0 {
				return c
			}
		default:
			if c := sign(strings.Compare(one.text, two.text)); c != 0 {
				return c
			}
		}
	}
	return sign(len(a.local) - len(b.local))
}

// pypiRead pulls a version apart, and says whether what it was given is a
// version at all.
func pypiRead(v string) (pypiVersion, bool) {
	// A byte above ASCII cannot appear in a version and can appear in a
	// lowering. Refused before the lowering rather than after, so that what is
	// matched is what arrived.
	for i := 0; i < len(v); i++ {
		if v[i] >= 0x80 {
			return pypiVersion{}, false
		}
	}
	found := pypiVersionPattern.FindStringSubmatch(strings.ToLower(v))
	if found == nil {
		return pypiVersion{}, false
	}
	part := func(name string) string {
		return found[pypiVersionPattern.SubexpIndex(name)]
	}

	read := pypiVersion{epoch: part("epoch"), preRank: pypiPreNone, devRank: 1}
	if read.epoch == "" {
		read.epoch = "0"
	}
	// Trailing zeros carry nothing, so "1.0.0" and "1" are one version.
	read.release = strings.Split(part("release"), ".")
	for len(read.release) > 0 && strings.Trim(read.release[len(read.release)-1], "0") == "" {
		read.release = read.release[:len(read.release)-1]
	}

	if letter := part("pre_l"); letter != "" {
		read.preRank, read.preN = pypiPreRanks[letter], pypiNumber(part("pre_n"))
	}
	// Two spellings of a post-release. A bare number after a hyphen is one,
	// which is what "1.0-5" is, and it carries no word to recognize it by.
	if number := part("post_n1"); number != "" {
		read.postRank, read.postN = 1, number
	} else if part("post_l") != "" {
		read.postRank, read.postN = 1, pypiNumber(part("post_n2"))
	}
	// Recognized by the whole development group rather than by its number,
	// which is optional: "1.0.dev" is a development release of an implicit
	// zero, and a local version spelled "dev" is not one at all.
	if part("dev") != "" {
		read.devRank, read.devN = 0, pypiNumber(part("dev_n"))
	}
	// Nothing but a development segment puts the version below every
	// pre-release rather than above the release it is a build of.
	if read.preRank == pypiPreNone && read.postRank == 0 && read.devRank == 0 {
		read.preRank = pypiPreDevOnly
	}

	if local := part("local"); local != "" {
		read.hasLocal = true
		for _, segment := range strings.FieldsFunc(local, func(r rune) bool {
			return r == '.' || r == '-' || r == '_'
		}) {
			read.local = append(read.local, pypiLocalPart{numeric: digits(segment), text: segment})
		}
	}
	return read, true
}

// pypiNumber is the count beside a suffix, where one that is absent counts as
// zero: "1.0a" and "1.0a0" are one version.
func pypiNumber(n string) string {
	if n == "" {
		return "0"
	}
	return n
}
