package vercmp_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// The cases below are NuGet's own, taken from the NuGet.Client project's
// versioning tests — `VersionComparerTests`, `NuGetVersionTest`,
// `SemVer201SpecTests`, `SemanticVersionTests` and `VersionParsingTests`.
// NuGet is published under the Apache License 2.0, which is this tree's own
// license. `NOTICE` records that.
//
// Every case that asks the loose parser whether a string is a version, or the
// default comparison how two versions order, is here. What is left out asks
// something this package has no counterpart for: the strict parser, which
// refuses a version with two numbers or four and is not what NuGet orders
// packages with, and the formatting of a version back into a string.

// nugetBelow is every pair the suite orders, the first below the second.
var nugetBelow = [][2]string{
	// VersionComparerTests: less under the default comparison.
	{"0.0.0", "1.0.0"},
	{"1.0.0", "1.1.0"},
	{"1.0.0", "1.0.1"},
	{"1.999.9999", "2.1.1"},
	{"1.0.0-BETA", "1.0.0-beta2"},
	{"1.0.0-beta+AA", "1.0.0+aa"},
	{"1.0.0-BETA", "1.0.0-beta.1+AA"},
	{"1.0.0-BETA.X.y.5.77.0+AA", "1.0.0-beta.x.y.5.79.0+aa"},
	{"1.0.0-BETA.X.y.5.79.0+AA", "1.0.0-beta.x.y.5.790.0+abc"},
	// NuGetVersionTest: the ordering operators.
	{"1.0", "1.0.1"},
	{"1.23", "1.231"},
	{"1.4.5.6", "1.45.6"},
	{"1.4.5.6", "1.4.5.60"},
	{"1.01", "1.10"},
	{"1.01-alpha", "1.10-beta"},
	{"1.01.0-RC-1", "1.10.0-rc-2"},
	{"1.01-RC-1", "1.01"},
	{"1.01", "1.2-preview"},
	// SemVer201SpecTests: the precedence rules of Semantic Versioning 2.0.
	{"1.2.3", "1.2.4"},
	{"1.2.3", "2.0.0"},
	{"9.9.9", "10.1.1"},
	{"1.2.3-alpha", "1.2.3"},
	{"1.2.3-2", "1.2.3-3"},
	{"1.2.3-1.9", "1.2.3-1.50"},
	{"1.2.3-2A", "1.2.3-3A"},
	{"1.2.3-1.50A", "1.2.3-1.9A"},
	{"1.2.3-999999", "1.2.3-Z"},
	{"1.2.3-A.999999", "1.2.3-A.56-2"},
	{"1.2.3-a", "1.2.3-a.2"},
	{"1.2.3-a.2.3.4", "1.2.3-a.2.3.4.5"},
}

// nugetDifferent is every pair the suite says is not one version, without
// saying which way round.
var nugetDifferent = [][2]string{
	// VersionComparerTests: not equal under the default comparison, where
	// the fourth number is compared. The suite's other "not equal" table is
	// not taken: it compares the two strings rather than two versions, so it
	// passes for any comparer, and one of its pairs — "1.0.0-BETA+AA" and
	// "1.0.0-beta" — is one version under NuGet's own.
	{"1.0", "1.0.0.1"},
	{"1.0+test", "1.0.0.1"},
	{"1.0.0.1-1.2.A", "1.0.0.1-1.2.a.A+A"},
	{"1.0.01", "1.0.1.2"},
}

// nugetSame is every pair the suite reads as one version.
var nugetSame = [][2]string{
	// VersionComparerTests: equal under the default comparison.
	{"1.0.0", "1.0.0"},
	{"1.0.0-BETA", "1.0.0-beta"},
	{"1.0.0-BETA+AA", "1.0.0-beta+aa"},
	{"1.0.0-BETA.X.y.5.77.0+AA", "1.0.0-beta.x.y.5.77.0+aa"},
	{"1.0.0", "1.0.0+beta"},
	{"1.0", "1.0.0.0"},
	{"1.0+test", "1.0.0.0"},
	{"1.0.0.1-1.2.A", "1.0.0.1-1.2.a+A"},
	{"1.0.01", "1.0.1.0"},
	// NuGetVersionTest: the equality operator.
	{"1.0", "1.0.0.0"},
	{"1.23.01", "1.23.1"},
	{"1.45.6", "1.45.6.0"},
	{"1.45.6-Alpha", "1.45.6-Alpha"},
	{"1.6.2-BeTa", "1.6.02-beta"},
	{"22.3.07     ", "22.3.07"},
	{"1.0", "1.0.0.0+beta"},
	{"1.0.0.0+beta.2", "1.0.0.0+beta.1"},
	{"1.0.0.0", "1.0.0"},
	// NuGetVersionTest: what a legacy version is read as.
	{"1.022", "1.22.0.0"},
	{"23.2.3", "23.2.3.0"},
	{"1.3.42.10133", "1.3.42.10133"},
	{"1.022-Beta", "1.22.0.0-Beta"},
	{"23.2.3-Alpha", "23.2.3.0-Alpha"},
	{"1.3.42.10133-PreRelease", "1.3.42.10133-PreRelease"},
	{"1.3.42.200930-RC-2", "1.3.42.200930-RC-2"},
	{"  1.022-Beta", "1.22.0.0-Beta"},
	{"23.2.3-Alpha  ", "23.2.3.0-Alpha"},
	{"    1.3.42.10133-PreRelease  ", "1.3.42.10133-PreRelease"},
	// NuGetVersionTest: whitespace around a number, and leading zeros.
	{"   19", "19.0.0.0"},
	{"   19.   19", "19.19.0.0"},
	{"   19.   19.   19", "19.19.19.0"},
	{"   19.   19.   19.   19", "19.19.19.19"},
	{"19   ", "19.0.0.0"},
	{"19   .19   ", "19.19.0.0"},
	{"19   .19   .19   ", "19.19.19.0"},
	{"19   .19   .19   .19   ", "19.19.19.19"},
	{"   19   ", "19.0.0.0"},
	{"   19   .   19   ", "19.19.0.0"},
	{"   19   .   19   .   19   ", "19.19.19.0"},
	{"   19   .   19   .   19   .   19   ", "19.19.19.19"},
	{"01.1.1.1", "1.1.1.1"},
	{"1.01.1.1", "1.1.1.1"},
	{"1.1.01.1", "1.1.1.1"},
	{"1.1.1.01", "1.1.1.1"},
	{"2147483647.1.1.1", "2147483647.1.1.1"},
	{"1.2147483647.1.1", "1.2147483647.1.1"},
	{"1.1.2147483647.1", "1.1.2147483647.1"},
	{"1.1.1.2147483647", "1.1.1.2147483647"},
	// VersionParsingTests: one to four numbers are one version.
	{"2", "2.0.0"},
	{"2.0", "2.0.0"},
	{"2.0.0.0", "2.0.0"},
	// SemVer201SpecTests and SemanticVersionTests: case, and metadata.
	{"1.2.3-a", "1.2.3-A"},
	{"1.2.3-A-b2-C", "1.2.3-a-B2-c"},
	{"1.2.3", "1.2.3+0"},
	{"1.2.3", "1.2.3+321"},
	{"1.2.3", "1.2.3+XYZ"},
	{"1.2.3-alpha", "1.2.3-alpha+0"},
	{"1.2.3-alpha", "1.2.3-alpha+10"},
	{"1.2.3-alpha", "1.2.3-alpha+beta"},
}

// nugetValid is every string the suite says the loose parser accepts, beyond
// those the pairs above already carry.
var nugetValid = []string{
	"1.0.0", "0.0.1", "1.2.3", "1.2.3-alpha",
	"1.2.3-X.y.3+Meta-2",
	"1.2.3-X.yZ.3.234.243.3242342+METADATA",
	"1.2.3-X.y3+0", "1.2.3-X+0", "1.2.3+0", "1.2.3-0",
	"2.3-alpha", "3.4.0.3-RC-3",
	"1.0.0-beta.x.y.5.79.0+aa", "1.0.0-beta.x.y.5.79.0+AA",
	"1.0-alpha", "1.0.0-b", "3.0.1.2", "2.1.4.3-pre-1",
	"1.0+A", "1.0-1.1", "1.0-1.1+B.B", "1.0.0009.01-1.1+A",
	"01.42.0", "01.0", "01.42.0-alpha", "01.42.0-alpha.1",
	"01.42.0-alpha+metadata", "01.42.0+metadata",
	"1.3.2-CTP-2-Refresh-Alpha",
	"1.0.0-Beta", "1.0.0-Beta.2", "1.0.0+MetaOnly", "1.0.0-Beta+Meta",
	"1.0.0-RC.X+MetaAA", "1.0.0-RC.X.35.A.3455+Meta-A-B-C",
	"0.0.0", "3.5.1", "234.234234.1111", "3.5.1+Meta", "3.5.1-x.y.z+AA",
	"1.2.3-X.yZ.3.234.243.32423423.4.23423.4324.234.234.3242",
	"1.2.3-X.yZ.3.234.243.32423423.4.23423+METADATA",
	// Accepted by the loose parser and refused only by the strict one.
	"2.7", "1.3.4.5", "1.3-alpha", "1.3 .4", "2.3.18.2-a",
	"01.2.3", "1.02.3", "1.2.03", "1", "1.2", "1.2.3.4", "1.2. 3", "1. 2.3",
	"00.2.3", "1.2.0030",
	"10.2.3", "13234.223.32222", "0.1.2", "1.0.0",
	"0.1.2-Alpha",
	"0.1.2-Alpha.2.34.5.453.345.345.345.345.A.B.bbbbbbb.Csdfdfdf",
	"0.1.2-Alpha-2-5Bdd", "0.1.2--", "0.1.2--B-C-", "0.1.2--B2.-.C.-A0-",
	"0.1.2+NoReleaseLabel",
	"0.1.2-02A", "0.1.2-2.02B", "0.1.2-2.A.02-", "0.1.2-A02.A",
	"0.1.2+02A", "0.1.2+A", "0.1.2+20349244.233.344.0",
	"0.1.2+203-49244.23-3.34-4.0-.-.-", "0.1.2+AAaaaaAAAaaaa", "0.1.2+-",
	"0.1.2+----.-.-.-", "0.1.2----+----",
	"0.1.2+02.02-02", "0.1.2+02", "0.1.2+000000",
	"0.1.2+AA-02A", "0.1.2+A.-A-02A",
}

// nugetInvalid is every string the suite says the loose parser refuses.
var nugetInvalid = []string{
	// NuGetVersionTest: not a valid version.
	"         ", "1beta", "1.2Av^c", "1.2..", "1.2.3.4.5", "1.2.3.Beta",
	"1.2.3.4This version is full of awesomeness!!", "So.is.this",
	"1.34.2Alpha", "1.34.2Release Candidate",
	"1.4.7-", "1.4.7-*", "1.4.7+*", "1.4.7-AA.01^", "1.4.7-AA.0A^",
	"1.4.7-A^A", "1.4.7+AA.01^",
	"1.2147483648", "1.1.2147483648", "1.1.1.2147483648",
	"1.1.1.1.2147483648", "10000000000000000000", "1.10000000000000000000",
	"1.1.10000000000000000000", "1.1.1.1.10000000000000000000",
	"1..2", "....", "..1",
	"-1.1.1.1", "1.-1.1.1", "1.1.-1.1", "1.1.1.-1",
	"1.", "1.1.", "1.1.1.", "1.1.1.1.", "1.1.1.1.1.",
	"1     1.1.1.1", "1.1     1.1.1", "1.1.1     1.1", "1.1.1.1     1",
	" .1.1.1", "1. .1.1", "1.1. .1", "1.1.1. ",
	"1 .", "1.1 .", "1.1.1 .", "1.1.1.1 .",
	"2147483648.2.3.4", "1.2147483648.3.4", "1.2.2147483648.4",
	"1.2.3.2147483648", "..1.2",
	"-1.2.3.4", "1.-2.3.4", "1.2.-3.4", "1.2.3.-4",
	"   1 9", "   19.   1 9", "   19.   19.   1 9", "   19.   19.   19.   1 9",
	"1 9   ", "19   .1 9   ", "19   .19   .1 9   ", "19   .19   .19   .1 9   ",
	"   1 9   ", "   19   .   1 9   ", "   19   .   19   .   1 9   ",
	"   19   .   19   .   19   .   1 9   ",
	// NuGetVersionTest: not even loosely a version.
	"", "NotAVersion", "v1.0.0",
	// SemVer201SpecTests: numbers, labels and metadata.
	"X.2.3", "1.2.Z", "X.Y.Z",
	"-1.2.3", "1.-2.3", "1.2.-3",
	"0.1.2-Alpha..2", "0.1.2-Alpha.", "0.1.2-.AA", "0.1.2-",
	"0.1.2-alp=ha", "0.1.2-alp┐jj", "0.1.2-a&444", "0.1.2-a.&.444",
	"0.1.2-02", "0.1.2-2.02", "0.1.2-2.A.02", "0.1.2-02.A",
	"0.1.2+ÄÄ", "0.1.2+22.2ÄÄ", "0.1.2+2+A",
	"0.1.2+02A.", "0.1.2+02..A", "0.1.2+",
	// SemanticVersionTests: refused by the strict parser, and by the loose one
	// too.
	"1.2.3-A..B", ".2.03", "1.2.", "1.2.3-a$b", "a.b.c", "1.2.3-00",
	"1.2.3-A.00.B",
}

func TestNuGetVersionsOrderTheWayNuGetOrdersThem(t *testing.T) {
	for _, each := range nugetBelow {
		bothWays(t, vercmp.NuGet, each[0], each[1], -1)
	}
	for _, each := range nugetDifferent {
		got, ok := vercmp.Order(vercmp.NuGet, each[0], each[1])
		if !ok {
			t.Errorf("%q against %q could not be ordered", each[0], each[1])
		} else if got == 0 {
			t.Errorf("%q and %q read as one version", each[0], each[1])
		}
	}
}

func TestOneNuGetVersionSpelledTwoWaysIsOneVersion(t *testing.T) {
	for _, each := range nugetSame {
		bothWays(t, vercmp.NuGet, each[0], each[1], 0)
	}
}

func TestTheVersionsNuGetParsesAreOrdered(t *testing.T) {
	for _, each := range nugetValid {
		if _, ok := vercmp.Order(vercmp.NuGet, each, "1.0"); !ok {
			t.Errorf("%q was refused, and NuGet parses it", each)
		}
	}
}

func TestTheVersionsNuGetRefusesAreRefused(t *testing.T) {
	for _, each := range nugetInvalid {
		if _, ok := vercmp.Order(vercmp.NuGet, each, "1.0"); ok {
			t.Errorf("%q was ordered, and NuGet refuses it", each)
		}
		if _, ok := vercmp.Order(vercmp.NuGet, "1.0", each); ok {
			t.Errorf("a version was ordered against %q, and NuGet refuses it", each)
		}
	}
}

func TestNuGetOrdersWhatItsOwnSuiteNeverPairs(t *testing.T) {
	// Transcribed rules the suite reaches only by parsing, never by ordering.
	for _, each := range []struct {
		a, b string
		want int
	}{
		// A label is a number only where it fits the reference's 32-bit
		// integer, so a longer run of digits is a word, and a word sorts above
		// every number.
		{"1.0.0-2147483647", "1.0.0-2147483648", -1},
		{"1.0.0-99999999999", "1.0.0-3", 1},
		// A label that is a hyphen and digits is a negative number to the
		// reference, which orders it below zero.
		{"1.0.0--1", "1.0.0-0", -1},
		// Words compare without regard to case, character by character.
		{"1.0.0-ALPHA", "1.0.0-beta", -1},
		// The fourth number decides after the first three agree.
		{"1.0.0.2", "1.0.0.10", -1},
	} {
		bothWays(t, vercmp.NuGet, each.a, each.b, each.want)
	}
}

func TestANuGetWordWhereAVersionBelongsIsRefused(t *testing.T) {
	// What an advisory writes where a version belongs. NuGet's own parser
	// refuses every one of these already; they are here because no reference
	// suite carries them.
	for _, not := range []string{"unfixed", "TBD", "none", "not fixed", "see the advisory"} {
		if _, ok := vercmp.Order(vercmp.NuGet, not, "1.0"); ok {
			t.Errorf("%q was ordered against a version", not)
		}
	}
}

func TestReachingANuGetReleaseReachesTheEarlierOnes(t *testing.T) {
	for _, each := range []struct {
		candidate, wanted string
		want              bool
	}{
		{"13.0.3", "13.0.1", true},
		{"13.0.1", "13.0.3", false},
		{"2.0.0", "2.0.0-rc.1", true},
		{"2.0.0-rc.1", "2.0.0", false},
		{"4.0.0.1", "4.0.0", true},
		{"1.0", "unfixed", false},
	} {
		if got := vercmp.Reaches(vercmp.NuGet, each.candidate, each.wanted); got != each.want {
			t.Errorf("%q reaching %q is %v, want %v", each.candidate, each.wanted, got, each.want)
		}
	}
}
