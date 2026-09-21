package vercmp_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// The cases below are Python's own, taken from the `packaging` project's test
// suite at `tests/test_version.py`. That project is the reference
// implementation of PEP 440 and is published under the Apache License 2.0 or
// the 2-clause BSD License at the taker's choice, both of which this tree
// already ships under. `NOTICE` records that.
//
// Taken rather than written, which the two distribution schemes above are not.
// The difference is the license and nothing else: their suites are
// GPL-licensed and could not be brought in, so cases for them were written
// here at the cost of nobody outside this tree having chosen them. These were
// chosen by the people who define the format, and they cover pairs nobody here
// would have thought to try.
//
// What is written here rather than taken is the refusal, because the
// reference implementation raises where this returns a second result, and the
// candidate set that one unreadable version leaves unranked.

// pypiAscending is every version in the suite, in the order PEP 440 puts them.
// Each one is strictly below the next, which is what the suite asserts.
var pypiAscending = []string{
	"1.0.dev0",
	"1.0.dev456",
	"1.0.dev456+local",
	"1.0a0",
	"1.0a0.post0.dev0",
	"1.0a0.post0",
	"1.0a1.dev1",
	"1.0a1.dev1+local",
	"1.0a1",
	"1.0a1+local",
	"1.0b0",
	"1.0b1.dev456",
	"1.0b2",
	"1.0b2.post345.dev456",
	"1.0b2.post345",
	"1.0b2-346",
	"1.0rc0",
	"1.0rc1.dev1",
	"1.0c1",
	"1.0rc2",
	"1.0",
	"1.0.post0.dev0",
	"1.0.post0",
	"1.0.post456.dev34",
	"1.0.post456",
	"1.0.post456+local",
	"1.0.1.dev1",
	"1.0.1a1",
	"1.0.1",
	"1.0.1+local",
	"1.0.1.post1",
	"1.1.dev1",
	"1.2+a",
	"1.2+abc",
	"1.2+abcdef",
	"1.2+def",
	"1.2+0",
	"1.2+1",
	"1.2+1.abc",
	"1.2+1.1",
	"1.2+1.1.0",
	"1.2+2",
	"1.2+123",
	"1.2+123456",
	"1.2.r32+123456",
	"1.2.rev33+123456",
	"1!1.0.dev0",
	"1!1.0.dev456",
	"1!1.0.dev456+local",
	"1!1.0a0",
	"1!1.0a0.post0.dev0",
	"1!1.0a0.post0",
	"1!1.0a1.dev1",
	"1!1.0a1.dev1+local",
	"1!1.0a1",
	"1!1.0a1+local",
	"1!1.0b0",
	"1!1.0b1.dev456",
	"1!1.0b2",
	"1!1.0b2.post345.dev456",
	"1!1.0b2.post345",
	"1!1.0b2-346",
	"1!1.0rc0",
	"1!1.0rc1.dev1",
	"1!1.0c1",
	"1!1.0rc2",
	"1!1.0",
	"1!1.0.post0.dev0",
	"1!1.0.post0",
	"1!1.0.post456.dev34",
	"1!1.0.post456",
	"1!1.0.post456+local",
	"1!1.0.1.dev1",
	"1!1.0.1a1",
	"1!1.0.1",
	"1!1.0.1+local",
	"1!1.0.1.post1",
	"1!1.1.dev1",
	"1!1.2+a",
	"1!1.2+abc",
	"1!1.2+abcdef",
	"1!1.2+def",
	"1!1.2+0",
	"1!1.2+1",
	"1!1.2+1.abc",
	"1!1.2+1.1",
	"1!1.2+1.1.0",
	"1!1.2+2",
	"1!1.2+123",
	"1!1.2+123456",
	"1!1.2.r32+123456",
	"1!1.2.rev33+123456",
}

// pypiSpellings pairs a version with the way PEP 440 writes the same
// version. The two compare equal.
var pypiSpellings = [][2]string{
	{"1.0dev", "1.0.dev0"},
	{"1.0.dev", "1.0.dev0"},
	{"1.0dev1", "1.0.dev1"},
	{"1.0-dev", "1.0.dev0"},
	{"1.0-dev1", "1.0.dev1"},
	{"1.0DEV", "1.0.dev0"},
	{"1.0.DEV", "1.0.dev0"},
	{"1.0DEV1", "1.0.dev1"},
	{"1.0.DEV1", "1.0.dev1"},
	{"1.0-DEV", "1.0.dev0"},
	{"1.0-DEV1", "1.0.dev1"},
	{"1.0a", "1.0a0"},
	{"1.0.a", "1.0a0"},
	{"1.0.a1", "1.0a1"},
	{"1.0-a", "1.0a0"},
	{"1.0-a1", "1.0a1"},
	{"1.0alpha", "1.0a0"},
	{"1.0.alpha", "1.0a0"},
	{"1.0.alpha1", "1.0a1"},
	{"1.0-alpha", "1.0a0"},
	{"1.0-alpha1", "1.0a1"},
	{"1.0A", "1.0a0"},
	{"1.0.A", "1.0a0"},
	{"1.0.A1", "1.0a1"},
	{"1.0-A", "1.0a0"},
	{"1.0-A1", "1.0a1"},
	{"1.0ALPHA", "1.0a0"},
	{"1.0.ALPHA", "1.0a0"},
	{"1.0.ALPHA1", "1.0a1"},
	{"1.0-ALPHA", "1.0a0"},
	{"1.0-ALPHA1", "1.0a1"},
	{"1.0b", "1.0b0"},
	{"1.0.b", "1.0b0"},
	{"1.0.b1", "1.0b1"},
	{"1.0-b", "1.0b0"},
	{"1.0-b1", "1.0b1"},
	{"1.0beta", "1.0b0"},
	{"1.0.beta", "1.0b0"},
	{"1.0.beta1", "1.0b1"},
	{"1.0-beta", "1.0b0"},
	{"1.0-beta1", "1.0b1"},
	{"1.0B", "1.0b0"},
	{"1.0.B", "1.0b0"},
	{"1.0.B1", "1.0b1"},
	{"1.0-B", "1.0b0"},
	{"1.0-B1", "1.0b1"},
	{"1.0BETA", "1.0b0"},
	{"1.0.BETA", "1.0b0"},
	{"1.0.BETA1", "1.0b1"},
	{"1.0-BETA", "1.0b0"},
	{"1.0-BETA1", "1.0b1"},
	{"1.0c", "1.0rc0"},
	{"1.0.c", "1.0rc0"},
	{"1.0.c1", "1.0rc1"},
	{"1.0-c", "1.0rc0"},
	{"1.0-c1", "1.0rc1"},
	{"1.0rc", "1.0rc0"},
	{"1.0.rc", "1.0rc0"},
	{"1.0.rc1", "1.0rc1"},
	{"1.0-rc", "1.0rc0"},
	{"1.0-rc1", "1.0rc1"},
	{"1.0C", "1.0rc0"},
	{"1.0.C", "1.0rc0"},
	{"1.0.C1", "1.0rc1"},
	{"1.0-C", "1.0rc0"},
	{"1.0-C1", "1.0rc1"},
	{"1.0RC", "1.0rc0"},
	{"1.0.RC", "1.0rc0"},
	{"1.0.RC1", "1.0rc1"},
	{"1.0-RC", "1.0rc0"},
	{"1.0-RC1", "1.0rc1"},
	{"1.0post", "1.0.post0"},
	{"1.0.post", "1.0.post0"},
	{"1.0post1", "1.0.post1"},
	{"1.0-post", "1.0.post0"},
	{"1.0-post1", "1.0.post1"},
	{"1.0POST", "1.0.post0"},
	{"1.0.POST", "1.0.post0"},
	{"1.0POST1", "1.0.post1"},
	{"1.0r", "1.0.post0"},
	{"1.0rev", "1.0.post0"},
	{"1.0.POST1", "1.0.post1"},
	{"1.0.r1", "1.0.post1"},
	{"1.0.rev1", "1.0.post1"},
	{"1.0-POST", "1.0.post0"},
	{"1.0-POST1", "1.0.post1"},
	{"1.0-5", "1.0.post5"},
	{"1.0-r5", "1.0.post5"},
	{"1.0-rev5", "1.0.post5"},
	{"1.0+AbC", "1.0+abc"},
	{"1.01", "1.1"},
	{"1.0a05", "1.0a5"},
	{"1.0b07", "1.0b7"},
	{"1.0c056", "1.0rc56"},
	{"1.0rc09", "1.0rc9"},
	{"1.0.post000", "1.0.post0"},
	{"1.1.dev09000", "1.1.dev9000"},
	{"00!1.2", "1.2"},
	{"0100!0.0", "100!0.0"},
	{"v1.0", "1.0"},
	{"   v1.0\t\n", "1.0"},
	{"\u202f1.0\t\u2029\n ", "1.0"},
}

// pypiNotVersions is the suite's own list of strings that are not versions.
var pypiNotVersions = []string{
	"french toast",
	"1.0+a+",
	"1.0++",
	"1.0+_foobar",
	"1.0+foo&asd",
	"1.0+1+1",
	"1. 0",
	"1 .0",
	"1. 0a1",
	"1 .0a1",
	"1.0 a1",
	"1.0a 1",
	"\u0660\u0661\u0662.\u0663\u0664\u0665.\u0666\u0667\u0668\u0669",
	".",
	"..",
	"1..0",
	"1.0.",
	".1.0",
	"1..2.3",
	"1.0+\u0130",
}

func TestPyPIVersionsOrderTheWayPEP440OrdersThem(t *testing.T) {
	// Every pair in the list, not only the neighbors. A comparator can order
	// each version below the next and still be wrong about a pair two apart,
	// which is what a chain of three suffixes makes possible.
	for i := range pypiAscending {
		for j := i + 1; j < len(pypiAscending); j++ {
			bothWays(t, vercmp.PyPI, pypiAscending[i], pypiAscending[j], -1)
		}
	}
}

func TestOnePyPIVersionSpelledTwoWaysIsOneVersion(t *testing.T) {
	// The spellings a version arrives in. A scanner reports what the package
	// index holds and an advisory reports what somebody typed, so "1.0-ALPHA1"
	// and "1.0a1" reach this from two directions and are one release.
	for _, each := range pypiSpellings {
		bothWays(t, vercmp.PyPI, each[0], each[1], 0)
		// And it reaches the same answer against a third version, which is
		// what says the two were read alike rather than merely compared alike.
		for _, against := range []string{"0.1", "99!0", "1.0+local"} {
			first, firstOK := vercmp.Order(vercmp.PyPI, each[0], against)
			second, secondOK := vercmp.Order(vercmp.PyPI, each[1], against)
			if firstOK != secondOK || first != second {
				t.Errorf("%q and %q are one version but compare %d and %d against %q",
					each[0], each[1], first, second, against)
			}
		}
	}
}

func TestAPyPIVersionThatIsNotOneIsRefused(t *testing.T) {
	// The refusal is PEP 440's own, which is what makes this scheme unlike the
	// distribution ones: the grammar already says what a version is, so a word
	// an advisory wrote where a version belongs needs no rule invented for it.
	for _, not := range append([]string{
		// What an advisory writes where a version belongs. Not in the suite,
		// because the reference implementation is asked about versions rather
		// than about what a security feed reports.
		"unfixed", "TBD", "none", "not fixed", "see the advisory",
		// A fork carrying a branch, and a local version with nothing local.
		"main-a1b2c3", "1.0+",
	}, pypiNotVersions...) {
		if _, ok := vercmp.Order(vercmp.PyPI, not, "1.0"); ok {
			t.Errorf("%q was ordered against a version", not)
		}
		if _, ok := vercmp.Order(vercmp.PyPI, "1.0", not); ok {
			t.Errorf("a version was ordered against %q", not)
		}
	}
}

func TestReachingAPyPIReleaseReachesTheEarlierOnes(t *testing.T) {
	// The question the picker asks, on the scheme rather than on the
	// comparison. A post-release reaches the release it follows and a
	// pre-release does not reach it.
	for _, each := range []struct {
		candidate, wanted string
		want              bool
	}{
		{"2.0", "1.9.3", true},
		{"1.0.post1", "1.0", true},
		{"1.0", "1.0.post1", false},
		{"1.0", "1.0rc1", true},
		{"1.0rc1", "1.0", false},
		{"1.0+ubuntu1", "1.0", true},
		{"1!0.1", "99.0", true},
		// Unreadable either side, so nothing is claimed.
		{"1.0", "unfixed", false},
		{"unfixed", "1.0", false},
	} {
		if got := vercmp.Reaches(vercmp.PyPI, each.candidate, each.wanted); got != each.want {
			t.Errorf("%q reaching %q is %v, want %v", each.candidate, each.wanted, got, each.want)
		}
	}
}

func TestAPyPILocalVersionSpelledLikeASuffixIsStillLocal(t *testing.T) {
	// The three suffixes are optional and two of them may carry no number, so
	// what says a version has one is the suffix having taken part in the match
	// rather than any text in it. Looked for in the string instead, a local
	// version somebody named "dev" turns a release into a development build of
	// itself — which sorts it below every pre-release rather than above the
	// release it was built from.
	for _, each := range []struct {
		a, b string
		want int
	}{
		{"1.0+dev", "1.0", 1},
		{"1.0+dev", "1.0.dev0", 1},
		{"1.0+devbuild.2", "1.0", 1},
		// And the development release itself still reads as one, with the
		// number it does not state counting as zero.
		{"1.0.dev", "1.0.dev0", 0},
		{"1.0.dev", "1.0", -1},
	} {
		bothWays(t, vercmp.PyPI, each.a, each.b, each.want)
	}
}

func TestAPyPIReleaseReadsTheSameWithTrailingZerosOrWithout(t *testing.T) {
	// The taken suite never compares a release against a shorter spelling of
	// itself, so nothing in it reaches the trim. What turns on it: an advisory
	// saying "fixed in 2.0" against an index publishing "2" would be two
	// releases rather than one, and the planner would offer an upgrade that is
	// already installed.
	for _, each := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1", 0},
		{"1.0.0", "1.0", 0},
		{"2.0.0.0", "2", 0},
		{"1!2.0.0", "1!2", 0},
		// And the trim stops at a part that says something, so a release is
		// not flattened into the one before it.
		{"1.0.0", "1.0.1", -1},
		{"1.0", "1.1", -1},
	} {
		bothWays(t, vercmp.PyPI, each.a, each.b, each.want)
	}
}
