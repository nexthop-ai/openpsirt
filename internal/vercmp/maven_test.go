package vercmp_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// The cases below are Maven's own, taken from the Apache Maven project's
// `ComparableVersionTest`. Maven is published under the Apache License 2.0,
// which is this tree's own license. `NOTICE` records that.
//
// Taken rather than written, for the same reason the PEP 440 cases are and the
// two distribution suites are not: the license permits it. Three of the
// tables below are a bug report each — a qualifier that sorted inconsistently,
// a number too long for the comparison to shortcut, and a qualifier written
// after a dot rather than a hyphen. Nobody reading a description of Maven
// versions arrives at any of them.

// mavenAscendingQualifiers is the suite's qualifier ordering, each entry
// strictly below every entry after it.
var mavenAscendingQualifiers = []string{
	"1-alpha2snapshot",
	"1-alpha2",
	"1-alpha-123",
	"1-beta-2",
	"1-beta123",
	"1-m2",
	"1-m11",
	"1-rc",
	"1-cr2",
	"1-rc123",
	"1-SNAPSHOT",
	"1",
	"1-sp",
	"1-sp2",
	"1-sp123",
	"1-abc",
	"1-def",
	"1-pom-1",
	"1-1-snapshot",
	"1-1",
	"1-2",
	"1-123",
}

// mavenAscendingNumbers is the suite's numeric ordering, on the same rule.
var mavenAscendingNumbers = []string{
	"2.0",
	"2.0.a",
	"2-1",
	"2.0.2",
	"2.0.123",
	"2.1.0",
	"2.1-a",
	"2.1b",
	"2.1-c",
	"2.1-1",
	"2.1.0.1",
	"2.2",
	"2.123",
	"11.a2",
	"11.a11",
	"11.b2",
	"11.b11",
	"11.m2",
	"11.m11",
	"11",
	"11.a",
	"11b",
	"11c",
	"11m",
}

// mavenSame pairs two spellings of one version.
var mavenSame = [][2]string{
	{"1", "1"},
	{"1", "1.0"},
	{"1", "1.0.0"},
	{"1.0", "1.0.0"},
	{"1", "1-0"},
	{"1", "1.0-0"},
	{"1.0", "1.0-0"},
	{"1a", "1-a"},
	{"1a", "1.0-a"},
	{"1a", "1.0.0-a"},
	{"1.0a", "1-a"},
	{"1.0.0a", "1-a"},
	{"1x", "1-x"},
	{"1x", "1.0-x"},
	{"1x", "1.0.0-x"},
	{"1.0x", "1-x"},
	{"1.0.0x", "1-x"},
	{"1ga", "1"},
	{"1release", "1"},
	{"1final", "1"},
	{"1cr", "1rc"},
	{"1a1", "1-alpha-1"},
	{"1b2", "1-beta-2"},
	{"1m3", "1-milestone-3"},
	{"1X", "1x"},
	{"1A", "1a"},
	{"1B", "1b"},
	{"1M", "1m"},
	{"1Ga", "1"},
	{"1GA", "1"},
	{"1RELEASE", "1"},
	{"1release", "1"},
	{"1RELeaSE", "1"},
	{"1Final", "1"},
	{"1FinaL", "1"},
	{"1FINAL", "1"},
	{"1Cr", "1Rc"},
	{"1cR", "1rC"},
	{"1m3", "1Milestone3"},
	{"1m3", "1MileStone3"},
	{"1m3", "1MILESTONE3"},
	// A version reads the same whatever the reader's language is. The suite
	// runs this under a Turkish locale, where lowering a capital I does not
	// give the letter i, which is what a lowering that asks the environment
	// gets wrong.
	{"1-abcdefghijklmnopqrstuvwxyz", "1-ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
	// Every length of a leading-zero run is the same number.
	{"0000000000000000001", "1"},
	{"000000000000000001", "1"},
	{"00000000000000001", "1"},
	{"0000000000000001", "1"},
	{"000000000000001", "1"},
	{"00000000000001", "1"},
	{"0000000000001", "1"},
	{"000000000001", "1"},
	{"00000000001", "1"},
	{"0000000001", "1"},
	{"000000001", "1"},
	{"00000001", "1"},
	{"0000001", "1"},
	{"000001", "1"},
	{"00001", "1"},
	{"0001", "1"},
	{"001", "1"},
	{"01", "1"},
	// Every length of a leading-zero run is the same number.
	{"0000000000000000000", "0"},
	{"000000000000000000", "0"},
	{"00000000000000000", "0"},
	{"0000000000000000", "0"},
	{"000000000000000", "0"},
	{"00000000000000", "0"},
	{"0000000000000", "0"},
	{"000000000000", "0"},
	{"00000000000", "0"},
	{"0000000000", "0"},
	{"000000000", "0"},
	{"00000000", "0"},
	{"0000000", "0"},
	{"000000", "0"},
	{"00000", "0"},
	{"0000", "0"},
	{"000", "0"},
	{"00", "0"},
}

// mavenAscendingPairs is the suite's pairwise ordering, the first below the
// second.
var mavenAscendingPairs = [][2]string{
	{"1", "2"},
	{"1.5", "2"},
	{"1", "2.5"},
	{"1.0", "1.1"},
	{"1.1", "1.2"},
	{"1.0.0", "1.1"},
	{"1.0.1", "1.1"},
	{"1.1", "1.2.0"},
	{"1.0-alpha-1", "1.0"},
	{"1.0-alpha-1", "1.0-alpha-2"},
	{"1.0-alpha-1", "1.0-beta-1"},
	{"1.0-beta-1", "1.0-SNAPSHOT"},
	{"1.0-SNAPSHOT", "1.0"},
	{"1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"},
	{"1.0", "1.0-1"},
	{"1.0-1", "1.0-2"},
	{"1.0.0", "1.0-1"},
	{"2.0-1", "2.0.1"},
	{"2.0.1-klm", "2.0.1-lmn"},
	{"2.0.1", "2.0.1-xyz"},
	{"2.0.1", "2.0.1-123"},
	{"2.0.1-xyz", "2.0.1-123"},
	// A qualifier in the middle of a version, which made the comparison
	// disagree with itself: a was above b and b above c while c was above a,
	// and sorting a list of them threw.
	{"6.1.0rc3", "6.1.0"},
	{"6.1.0rc3", "6.1H.5-beta"},
	{"6.1.0", "6.1H.5-beta"},
	// Numbers past what the comparison shortcuts on, at four widths.
	{"20190126.230843", "1234567890.12345"},
	{"1234567890.12345", "123456789012345.1H.5-beta"},
	{"20190126.230843", "123456789012345.1H.5-beta"},
	{"123456789012345.1H.5-beta", "12345678901234567890.1H.5-beta"},
	{"1234567890.12345", "12345678901234567890.1H.5-beta"},
	{"20190126.230843", "12345678901234567890.1H.5-beta"},
	// A qualifier written after a zero, which used to read as the release
	// itself and made two different pre-releases both equal to it.
	{"1-0.alpha", "1"},
	{"1-0.beta", "1"},
	{"1-0.alpha", "1-0.beta"},
}

// mavenAfterADot is every word the suite checks the dot rule against: one
// written after a dot is below the same word written after a hyphen, and a
// word after a dot at the end of a version is the version itself.
var mavenAfterADot = []string{
	"abc",
	"alpha",
	"a",
	"beta",
	"b",
	"def",
	"milestone",
	"m",
	"RC",
}

func TestMavenVersionsOrderTheWayMavenOrdersThem(t *testing.T) {
	// Every pair in each list, not only the neighbors, which is what the suite
	// does: an ordering can place each entry below the next and still be
	// wrong two apart, and a list sorted with one that is throws rather than
	// sorting badly.
	for _, ascending := range [][]string{mavenAscendingQualifiers, mavenAscendingNumbers} {
		for i := range ascending {
			for j := i + 1; j < len(ascending); j++ {
				bothWays(t, vercmp.Maven, ascending[i], ascending[j], -1)
			}
		}
	}
	for _, each := range mavenAscendingPairs {
		bothWays(t, vercmp.Maven, each[0], each[1], -1)
	}
}

func TestOneMavenVersionSpelledTwoWaysIsOneVersion(t *testing.T) {
	for _, each := range mavenSame {
		bothWays(t, vercmp.Maven, each[0], each[1], 0)
		// And against a third version, which is what says the two were read
		// alike rather than merely compared alike.
		for _, against := range []string{"0.1", "1.0-alpha-1", "99"} {
			first, firstOK := vercmp.Order(vercmp.Maven, each[0], against)
			second, secondOK := vercmp.Order(vercmp.Maven, each[1], against)
			if firstOK != secondOK || first != second {
				t.Errorf("%q and %q are one version but compare %d and %d against %q",
					each[0], each[1], first, second, against)
			}
		}
	}
}

func TestAMavenWordAfterADotIsBelowTheSameWordAfterAHyphen(t *testing.T) {
	// The rule that makes the version a tree rather than a list, over every
	// word the suite checks it against — known words, their short spellings,
	// and words Maven has never heard of.
	for _, word := range mavenAfterADot {
		bothWays(t, vercmp.Maven, "1.0.0."+word+"1", "1.0.0-"+word+"2", -1)
		bothWays(t, vercmp.Maven, "2-"+word, "2.0."+word, 0)
		bothWays(t, vercmp.Maven, "2-"+word, "2.0.0."+word, 0)
		bothWays(t, vercmp.Maven, "2.0."+word, "2.0.0."+word, 0)
	}
}

func TestAMavenVersionThatIsNotOneIsRefused(t *testing.T) {
	// Maven's comparison answers for any two strings, so the rule for what a
	// version is belongs here rather than there. It is the one the
	// distribution schemes state: a leading digit, and only the characters a
	// version may hold.
	for _, not := range []string{
		// What an advisory writes where a version belongs. Ordered by Maven
		// itself, and "unfixed" is a word it has never heard of, which sorts
		// above every release.
		"unfixed", "TBD", "none", "not fixed", "see the advisory",
		// The words Maven itself takes instead of a version.
		"RELEASE", "LATEST",
		// No leading digit.
		"v1.0", "alpha-1", "-1.0",
		// Bytes outside what a version may hold. Read as part of a word, the
		// comparison would answer about a string nobody wrote.
		"1.1.α", "1.0 1", "1.0/2",
	} {
		if _, ok := vercmp.Order(vercmp.Maven, not, "1.0"); ok {
			t.Errorf("%q was ordered against a version", not)
		}
		if _, ok := vercmp.Order(vercmp.Maven, "1.0", not); ok {
			t.Errorf("a version was ordered against %q", not)
		}
	}
}

func TestReachingAMavenReleaseReachesTheEarlierOnes(t *testing.T) {
	for _, each := range []struct {
		candidate, wanted string
		want              bool
	}{
		{"2.0", "1.9.3", true},
		{"1.0", "1.0-SNAPSHOT", true},
		{"1.0-SNAPSHOT", "1.0", false},
		{"1.0-sp1", "1.0", true},
		{"1.0", "1.0-sp1", false},
		{"1.0.0", "1.0", true},
		// Unreadable either side, so nothing is claimed.
		{"1.0", "unfixed", false},
		{"unfixed", "1.0", false},
	} {
		if got := vercmp.Reaches(vercmp.Maven, each.candidate, each.wanted); got != each.want {
			t.Errorf("%q reaching %q is %v, want %v", each.candidate, each.wanted, got, each.want)
		}
	}
}
