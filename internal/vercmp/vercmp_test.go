package vercmp_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

func TestDebianVersionsOrderTheWayDpkgOrdersThem(t *testing.T) {
	// The cases that catch a comparison written from intuition: a tilde sorts
	// before the release it leads to and before the end of a string, leading
	// zeros carry no value, an epoch outranks everything after it, and a
	// revision only decides where the upstream versions match.
	for _, each := range []struct {
		a, b string
		want int
	}{
		{"6.12.41-1", "6.12.107-1", -1},
		{"6.12.107-1", "6.12.41-1", 1},
		{"6.12.41-1", "6.12.41-1", 0},
		// 100 is larger than 94 even though "1" sorts before "9".
		{"6.12.94-1", "6.12.100-1", -1},
		// A revision decides only once the upstream versions match.
		{"8.14.1-2+deb13u4", "8.14.1-2+deb13u5", -1},
		{"8.14.1-2+deb13u4", "8.15.0-1", -1},
		// A tilde sorts before everything, including the end of the string.
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0", "1.0a", -1},
		// Leading zeros carry no value.
		{"1.007", "1.7", 0},
		// An epoch outranks the version after it.
		{"1:1.0", "2.0", 1},
		{"2.0", "1:1.0", -1},
		{"1:1.0", "1:1.0", 0},
	} {
		got, ok := vercmp.Order(vercmp.Debian, each.a, each.b)
		if !ok {
			t.Errorf("%q against %q could not be ordered", each.a, each.b)
			continue
		}
		if got != each.want {
			t.Errorf("%q against %q is %d, want %d", each.a, each.b, got, each.want)
		}
	}
}

func TestSemanticVersionsOrderAndAPreReleaseComesFirst(t *testing.T) {
	for _, each := range []struct {
		a, b string
		want int
	}{
		{"1.25.11", "1.26.6", -1},
		{"1.26.6", "1.26.6", 0},
		{"v0.87.0", "v0.118.0", -1},
		// An absent part is zero, so these are one version.
		{"1.2", "1.2.0", 0},
		// A pre-release is not yet the release it leads to.
		{"1.27.0-rc.2", "1.27.0", -1},
		{"1.27.0-rc.2", "1.27.0-rc.3", -1},
		// Two digits. Compared as one string these invert, because the
		// comparison stops at the first digit and never reaches the second.
		{"1.27.0-rc.2", "1.27.0-rc.10", -1},
		{"1.0.0-beta.9", "1.0.0-beta.10", -1},
		{"1.0.0-2", "1.0.0-11", -1},
		// A numeric identifier ranks below an alphanumeric one, and a suffix
		// that runs out while matching ranks below the longer one.
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0-rc", "1.0.0-rc.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		// Build metadata says nothing about order.
		{"v28.5.2+incompatible", "v28.5.2", 0},
		// The same comparisons the other way round, because three arms fire
		// only when a sorts *after* b: a release outranking its own
		// pre-release, an alphanumeric identifier outranking a numeric one,
		// and two differing alphabetic identifiers. Without the mirrors,
		// "alpha before beta" is asserted nowhere and flipping the numeric
		// rule breaks antisymmetry rather than merely an answer.
		{"1.27.0", "1.27.0-rc.2", 1},
		{"1.0.0-alpha", "1.0.0-1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-alpha", 1},
		{"1.0.0-rc.1", "1.0.0-rc", 1},
	} {
		got, ok := vercmp.Order(vercmp.Semantic, each.a, each.b)
		if !ok {
			t.Errorf("%q against %q could not be ordered", each.a, each.b)
			continue
		}
		if got != each.want {
			t.Errorf("%q against %q is %d, want %d", each.a, each.b, got, each.want)
		}
	}
}

func TestOrderingIsAntisymmetric(t *testing.T) {
	// A comparator read as a comparator rather than as a table of answers.
	// Every arm that decides an order has a mirror, and a rule that returns
	// the same sign both ways is not a wrong answer but a broken ordering: a
	// list sorted with it depends on the order it was already in.
	for _, each := range []struct {
		scheme vercmp.Scheme
		a, b   string
	}{
		{vercmp.Debian, "6.12.41-1", "6.12.107-1"},
		{vercmp.Debian, "1.0~rc1", "1.0"},
		{vercmp.Debian, "1.007", "1.7"},
		{vercmp.Debian, "1:1.0", "2.0"},
		{vercmp.Semantic, "1.27.0-rc.2", "1.27.0"},
		{vercmp.Semantic, "1.0.0-1", "1.0.0-alpha"},
		{vercmp.Semantic, "1.0.0-alpha", "1.0.0-beta"},
		{vercmp.Semantic, "1.0.0-rc", "1.0.0-rc.1"},
		{vercmp.Semantic, "1.2", "1.2.0"},
		{vercmp.RPM, "1.0", "1.0~rc1"},
		{vercmp.RPM, "1.0", "1.0^20240101"},
		{vercmp.RPM, "1.a", "1.2"},
		{vercmp.RPM, "1:1.0-1", "2.0-1"},
		{vercmp.RPM, "1.0-1", "1.0-2"},
		{vercmp.APK, "1.2.0_rc1", "1.2.0"},
		{vercmp.APK, "1.2.0", "1.2.0_p1"},
		{vercmp.APK, "1.2.0-r1", "1.2.0-r2"},
		{vercmp.APK, "8.2.0015", "8.2.002"},
		{vercmp.APK, "1.2.0_alpha", "1.2.0_beta"},
		{vercmp.PyPI, "1.0.dev1", "1.0a1"},
		{vercmp.PyPI, "1.0", "1.0.post1"},
		{vercmp.PyPI, "1.0", "1.0+local"},
		{vercmp.PyPI, "1.0+abc", "1.0+1"},
		{vercmp.PyPI, "1!0.1", "2.0"},
		{vercmp.Maven, "1-alpha-1", "1"},
		{vercmp.Maven, "1", "1-sp"},
		{vercmp.Maven, "1.0.0.rc1", "1.0.0-rc2"},
		{vercmp.Maven, "1-snapshot", "1"},
		{vercmp.Maven, "1", "1-abc"},
	} {
		forward, ok := vercmp.Order(each.scheme, each.a, each.b)
		if !ok {
			t.Errorf("%q against %q could not be ordered", each.a, each.b)
			continue
		}
		back, ok := vercmp.Order(each.scheme, each.b, each.a)
		if !ok {
			t.Errorf("%q against %q could not be ordered", each.b, each.a)
			continue
		}
		if forward != -back {
			t.Errorf("%q against %q is %d and the reverse is %d, want the opposite sign",
				each.a, each.b, forward, back)
		}
	}
}

func TestAnEcosystemIsOrderedByTheSchemeItsIdentifierNames(t *testing.T) {
	// Every table above passes the scheme in as a literal, so nothing else
	// here reaches SchemeOf at all — including the default arm, which is every
	// ecosystem whose algorithm is not written here. An ecosystem added to the
	// wrong arm orders its versions by somebody else's rules.
	for _, each := range []struct {
		ecosystem string
		want      vercmp.Scheme
	}{
		{"deb", vercmp.Debian},
		// Read without regard to capitals, because it arrives out of a
		// package identifier somebody else wrote.
		{"DEB", vercmp.Debian},
		{"golang", vercmp.Semantic},
		{"npm", vercmp.Semantic},
		{"cargo", vercmp.Semantic},
		{"rpm", vercmp.RPM},
		{"apk", vercmp.APK},
		{"pypi", vercmp.PyPI},
		{"maven", vercmp.Maven},
		// Ecosystems that plainly do have an ordering, and whose algorithm is
		// not written here. Claiming one is the confident wrong answer this
		// package exists to refuse.
		{"gem", vercmp.Unordered},
		{"generic", vercmp.Unordered},
		{"oci", vercmp.Unordered},
		{"", vercmp.Unordered},
	} {
		if got := vercmp.SchemeOf(each.ecosystem); got != each.want {
			t.Errorf("%q is ordered as %v, want %v", each.ecosystem, got, each.want)
		}
	}
}

func TestWhatCannotBeOrderedIsRefusedRatherThanGuessedAt(t *testing.T) {
	// The whole reason the second result exists. A confident answer here is
	// worse than none, because it arrives as a recommendation somebody
	// schedules a release around.
	for _, each := range []struct {
		scheme vercmp.Scheme
		a, b   string
	}{
		// A runtime naming itself after its own toolchain.
		{vercmp.Semantic, "go1.26.3", "go1.27.1"},
		// A fork carrying a branch instead of a version.
		{vercmp.Semantic, "main-a1b2c3", "1.0.0"},
		// Half a parse is not an answer.
		{vercmp.Semantic, "1.0.0", "not-a-version"},
		// An ecosystem whose algorithm is not written here.
		{vercmp.Unordered, "1.0", "2.0"},
		// Nothing to compare.
		{vercmp.Debian, "", "1.0"},
		// A word an advisory wrote where a version belongs. The comparison
		// answers for any pair of strings, which reads as a scheme that never
		// fails: a letter outranks a digit, so "unfixed" sorts above every
		// real release and is recommended as the upgrade.
		{vercmp.Debian, "unfixed", "1.0-1"},
		{vercmp.Debian, "TBD", "1.0-1"},
		{vercmp.Debian, "see the advisory", "1.0-1"},
		// An upstream version begins with a digit, which is Debian policy's
		// own rule and what separates a version from a word.
		{vercmp.Debian, "v1.0-1", "1.0-1"},
		// An epoch is digits or it is not an epoch.
		{vercmp.Debian, "next:1.0-1", "1.0-1"},
	} {
		if _, ok := vercmp.Order(each.scheme, each.a, each.b); ok {
			t.Errorf("%q against %q was ordered, want a refusal", each.a, each.b)
		}
	}
}

func TestReachingAVersionReachesEveryEarlierOne(t *testing.T) {
	// A picker's own question. An issue fixed in an earlier release is closed
	// by a later one, and the kernel is the case that makes it matter: the
	// newest release names two of its own and carries every fix before it.
	if !vercmp.Reaches(vercmp.Debian, "6.12.107-1", "6.12.100-1") {
		t.Error("the newest release does not reach an earlier one")
	}
	if vercmp.Reaches(vercmp.Debian, "6.12.100-1", "6.12.107-1") {
		t.Error("an earlier release reaches a later one")
	}
	// A version reaches itself, whatever the scheme — which is what keeps an
	// exact match counted where nothing can be ordered.
	if !vercmp.Reaches(vercmp.Unordered, "go1.26.3", "go1.26.3") {
		t.Error("a version does not reach itself")
	}
	// And reaches nothing else there, rather than guessing.
	if vercmp.Reaches(vercmp.Unordered, "go1.27.1", "go1.26.3") {
		t.Error("an unordered pair was treated as reachable")
	}
}

func TestTheSchemeFollowsThePackageIdentifierARealScanCarries(t *testing.T) {
	// The ecosystem reaching SchemeOf is read out of a package identifier, so
	// the spelling that matters is the one a scanner actually emits rather
	// than the word somebody would pick for the ecosystem.
	for _, each := range []struct {
		purl string
		want vercmp.Scheme
	}{
		{"pkg:rpm/fedora/openssl@3.2.1-1.fc39?arch=x86_64", vercmp.RPM},
		{"pkg:rpm/redhat/kernel@5.14.0-427.el9", vercmp.RPM},
		{"pkg:apk/alpine/busybox@1.37.0-r14?arch=x86_64", vercmp.APK},
		{"pkg:deb/debian/libc6@2.41", vercmp.Debian},
		{"pkg:golang/github.com/example/mod@v1.2.3", vercmp.Semantic},
		{"pkg:pypi/requests@2.31.0", vercmp.PyPI},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", vercmp.Maven},
		{"pkg:gem/rack@3.1.8", vercmp.Unordered},
	} {
		if got := vercmp.SchemeOf(graph.EcosystemOf(each.purl)); got != each.want {
			t.Errorf("%s is ordered as %v, want %v", each.purl, got, each.want)
		}
	}
}

func TestADistributionUpgradeReachesWhatItLeavesBehind(t *testing.T) {
	// The planner's own question, through the two new schemes: moving to this
	// version also closes what these earlier ones fixed.
	for _, each := range []struct {
		scheme            vercmp.Scheme
		candidate, wanted string
		want              bool
	}{
		{vercmp.RPM, "3.2.1-2.fc39", "3.2.1-1.fc39", true},
		{vercmp.RPM, "3.2.1-1.fc39", "3.2.1-2.fc39", false},
		{vercmp.RPM, "1:1.0-1", "0.9-1", true},
		{vercmp.RPM, "1.0-1", "1.0~rc1-1", true},
		{vercmp.RPM, "1.0~rc1-1", "1.0-1", false},
		{vercmp.APK, "1.37.0-r15", "1.37.0-r14", true},
		{vercmp.APK, "1.37.0-r14", "1.37.0-r15", false},
		{vercmp.APK, "1.2.0", "1.2.0_rc1", true},
		{vercmp.APK, "1.2.0_rc1", "1.2.0", false},
		{vercmp.APK, "1.2.0_p1", "1.2.0", true},
		// Refused rather than guessed, which answers false: an upgrade never
		// claims to close what could not be ordered against it.
		{vercmp.APK, "1.2.0", "not a version", false},
		{vercmp.RPM, "1.0-1", "unfixed", false},
	} {
		if got := vercmp.Reaches(each.scheme, each.candidate, each.wanted); got != each.want {
			t.Errorf("%v: reaching %q from %q is %v, want %v",
				each.scheme, each.wanted, each.candidate, got, each.want)
		}
	}
}

func TestAlpineOrdersTheTokensItsOwnSuiteNeverPairs(t *testing.T) {
	// A commit hash is the one token the published suite never orders against
	// another kind: three of its lines carry one and all three have a hash on
	// both sides, so every one is decided inside the token. Where the hash
	// sits among the tokens decides real answers — the tail rule compares
	// which token each version stopped on — and moving it would leave that
	// suite green.
	//
	// The same shape the two older schemes have beside their vendored cases,
	// and for the same reason: what a published suite does not pair is written
	// down here rather than left to whichever order the constants happen to be
	// declared in.
	for _, each := range []struct {
		a, b string
		want int
	}{
		// A hash follows the version it was taken of.
		{"1.0", "1.0~abcd", -1},
		// And outranks a bare revision. Where two versions agree as far as
		// one of them goes, the one that stopped on the earlier token is the
		// greater — a hash is part of what the version is, and a revision is
		// the packaging around it.
		{"1.0~abcd", "1.0-r1", 1},
		// And follows a suffix, which is part of what the version calls
		// itself rather than a note about where it came from.
		{"1.0_p1", "1.0~abcd", 1},
		{"1.0~abcd", "1.0_alpha1", 1},
		// Two hashes of one version compare as text, which is all anybody can
		// do with them.
		{"1.0~abcd", "1.0~bbcd", -1},
	} {
		got, ok := vercmp.Order(vercmp.APK, each.a, each.b)
		if !ok {
			t.Errorf("%q against %q could not be ordered", each.a, each.b)
			continue
		}
		if got != each.want {
			t.Errorf("%q against %q is %d, want %d", each.a, each.b, got, each.want)
		}
		back, ok := vercmp.Order(vercmp.APK, each.b, each.a)
		if !ok || back != -each.want {
			t.Errorf("%q against %q is %d, and back again is %d", each.a, each.b, got, back)
		}
	}
}

// The two distribution schemes are checked against cases written here rather
// than against the suites their projects publish.
//
// Those suites are GPL-licensed and this tree is Apache-2.0, so they are not
// taken — the same answer `internal/sbom/testdata` already gives about the
// sample source beside the documents it does take. What is kept is the
// knowledge: every rule each algorithm has is a case below, and the ones that
// contradict what anybody would write from the format description say so.
//
// The cost of writing our own is that nobody else chose the cases, so a
// pair nobody here thought of is not covered. Against that, each case names
// the rule it pins, which a borrowed suite does not.

func TestRPMVersionsOrderTheWayRpmvercmpOrdersThem(t *testing.T) {
	for _, each := range []struct {
		what string
		a, b string
		want int
	}{
		{"the same version", "1.0", "1.0", 0},
		{"a larger number", "2.0", "1.0", 1},
		{"a further segment", "2.0.1", "2.0", 1},
		{"letters after the numbers", "2.0.1a", "2.0.1", 1},

		// Every non-alphanumeric is a separator, so how many there are and
		// which they are says nothing.
		{"a dot and an underscore are one separator", "1.2", "1_2", 0},
		{"two separators are one", "1.2", "1..2", 0},

		// Leading zeros carry no value at all, which is the one most
		// likely to be written wrong: these are the same version, not
		// neighbours.
		{"a run of zeros is the number it spells", "10.0001", "10.1", 0},
		{"and so is a single one", "1.007", "1.7", 0},

		// A digit run is compared as a number, so the longer one wins once
		// the zeros are gone — never as text, which would order 10 below 2.
		{"ten is more than one", "5.5p10", "5.5p1", 1},
		{"a letter run is compared as text", "10b2", "10a1", 1},

		// A numeric run outranks an alphabetic one at the same position.
		{"a number outranks a letter", "1.2", "1.a", 1},
		// That is why a release candidate spelled as a further segment is
		// *newer* than the release: the letters are extra, not a pre-release
		// marker. rpm has a character for that and this is not it.
		{"a trailing segment of letters is more, not less", "6.0.rc1", "6.0", 1},

		// The tilde is that character: it sorts before everything, the end of
		// the string included.
		{"a tilde precedes the release it leads to", "1.0~rc1", "1.0", -1},
		{"two tildes compare after it", "1.0~rc2", "1.0~rc1", 1},
		{"and a tilde inside a tilde is earlier still", "1.0~rc1~git123", "1.0~rc1", -1},

		// The caret is the mirror: after the end of the string, before
		// anything that follows it.
		{"a caret follows the release it came after", "1.0^", "1.0", 1},
		{"a caret follows with content too", "1.0^git1", "1.0", 1},
		{"and precedes the next version", "1.0^20160101", "1.0.1", -1},
		// That is not the same as preceding a longer number in the same
		// segment: 0 against 01 is a number against a number.
		{"a caret does not outrank a larger segment", "1.0^git1", "1.01", -1},

		// The epoch decides before anything else is read.
		{"an epoch outranks the version", "1:1.0", "2.0", 1},
		{"an absent epoch is zero", "0:1.0", "1.0", 0},
		// And the release is read after the version, not before it.
		{"the release breaks a tie", "1.0-2", "1.0-1", 1},
		{"and never outranks the version", "1.0-9", "1.1-1", -1},
	} {
		t.Run(each.what, func(t *testing.T) {
			bothWays(t, vercmp.RPM, each.a, each.b, each.want)
		})
	}
}

func TestAlpineVersionsOrderTheWayApkOrdersThem(t *testing.T) {
	for _, each := range []struct {
		what string
		a, b string
		want int
	}{
		{"the same version", "1.0", "1.0", 0},
		{"a larger first number", "20050405", "2.38", 1},
		{"a further part", "1.0.1", "1.0", 1},
		{"a letter after the numbers", "1.0a", "1.0", 1},

		// A part with a leading zero is compared as text, not as a
		// number, which is the rule nothing in the format description says
		// and the one that reverses the obvious answer.
		{"a leading zero makes a part a fraction", "8.2.0015", "8.2.002", -1},
		{"and so orders 07 below 10", "1.02.07", "1.02.10", -1},
		// Without one, the parts are numbers and the longer run is larger.
		{"without a leading zero it is a number", "1.10", "1.9", 1},

		// The suffixes are an ordered, closed list: four lead to a release,
		// and the rest follow one.
		{"alpha precedes beta", "1.0_alpha", "1.0_beta", -1},
		{"beta precedes a prerelease", "1.0_beta", "1.0_pre", -1},
		{"a prerelease precedes a candidate", "1.0_pre", "1.0_rc", -1},
		{"a candidate precedes the release", "1.0_rc1", "1.0", -1},
		{"and a post-release follows it", "1.0_p1", "1.0", 1},
		{"in the order the list states", "1.0_cvs", "1.0_git", -1},
		{"a suffix number is a number", "1.0_alpha2", "1.0_alpha", 1},

		// A revision is the packaging around a version, read last.
		{"a revision breaks a tie", "1.0-r2", "1.0-r1", 1},
		{"and never outranks the version", "1.0-r9", "1.1-r0", -1},

		// A commit hash is part of what the version is, so it outranks a bare
		// revision and is outranked by a suffix.
		{"a hash follows the version it was taken of", "1.0~abcd", "1.0", 1},
		{"a hash outranks a bare revision", "1.0~abcd", "1.0-r1", 1},
		{"a suffix outranks a hash", "1.0_p1", "1.0~abcd", 1},
		{"a pre-release suffix does not", "1.0_alpha1", "1.0~abcd", -1},
		{"two hashes compare as text", "1.0~bbcd", "1.0~abcd", 1},
		{"a revision is read after a hash", "1.0~abcd-r1", "1.0~abcd-r0", 1},
	} {
		t.Run(each.what, func(t *testing.T) {
			bothWays(t, vercmp.APK, each.a, each.b, each.want)
		})
	}
}

func TestAlpineReadsAVersionOrRefusesTheWholeString(t *testing.T) {
	// Alpine's reader is a token sequence, and which token may follow which is
	// what makes a string a version at all. Its own tool sorts what it cannot
	// read as text; this refuses, so what counts as unreadable is worth
	// stating case by case.
	for _, each := range []struct {
		what    string
		version string
		reads   bool
	}{
		{"numbers", "1.2.3", true},
		{"a letter after the numbers", "1.2c", true},
		{"a suffix", "1.2_pre2", true},
		{"a suffix and a count", "1.2_alpha1", true},
		{"two suffixes", "0.1_alpha1_pre2", true},
		{"a hash", "0.1_pre2~1234abcd", true},
		{"a revision", "1.2-r0", true},
		{"everything at once", "0.1_git20240101_pre1", true},

		// One letter at most, and only where the numbers end.
		{"two letters", "0.1bc", false},
		{"a letter then a number", "0.1a1", false},
		{"a letter then a part", "0.1a.1", false},
		// The suffix list is closed, so a name not in it is not a version —
		// which is the rule that makes an unfamiliar spelling a refusal
		// rather than a guess.
		{"a suffix nobody defined", "0.1_foobar", false},
		{"an empty suffix", "0.1_", false},
		{"a doubled separator", "0.1__alpha", false},
		// A hash is hexadecimal and a revision is "-r" and digits.
		{"a hash of nothing", "0.1_pre2~", false},
		{"a hash that is not hexadecimal", "0.1_pre2~1234xbcd", false},
		{"a revision of nothing", "0.1-r", false},
		{"two revisions", "0.1-r2-r3", false},
		{"something after the revision", "0.1-r2_pre1", false},
		// And it has to start with a number.
		{"a bare word", "a", false},
		{"a leading dot", ".1", false},
		{"a leading suffix", "_pre1", false},
	} {
		t.Run(each.what, func(t *testing.T) {
			// Asked by ordering it against itself, which is the only way to
			// ask through what this package offers: a version that reads
			// compares equal to itself and one that does not is refused.
			if _, ok := vercmp.Order(vercmp.APK, each.version, each.version); ok != each.reads {
				t.Errorf("%q reads as a version: %v, want %v", each.version, ok, each.reads)
			}
		})
	}
}

func TestADistributionVersionThatIsNotOneIsRefused(t *testing.T) {
	// Both distribution comparisons answer for any two strings, which reads as
	// a scheme that never fails. What an advisory wrote where a version
	// belongs then outranked every real release, because a letter sorts above
	// a digit.
	for _, scheme := range []vercmp.Scheme{vercmp.RPM, vercmp.Debian} {
		for _, not := range []string{
			"unfixed", "TBD", "none", "not fixed", "", "  ",
			// No leading digit, which is the rule each scheme states for
			// itself.
			"xyz10", "v1.0", "-1.0",
			// Bytes outside what a version may hold. The comparison would
			// skip them as separators and answer about what was left, which
			// is an answer about a different string. Inside the version
			// rather than around it: space at either end is trimmed before
			// anything reads the string, Unicode space included.
			"1.1.α", "1.0 1",
		} {
			if _, ok := vercmp.Order(scheme, not, "1.0"); ok {
				t.Errorf("%v ordered %q against a version", scheme, not)
			}
			if _, ok := vercmp.Order(scheme, "1.0", not); ok {
				t.Errorf("%v ordered a version against %q", scheme, not)
			}
		}
	}
}

// bothWays asserts the order and that reversing the pair reverses the answer.
//
// A comparator returning the same sign in both directions is not one wrong
// answer, it is a broken ordering: a list sorted with it depends on the order
// it was already in, which no single case shows.
func bothWays(t *testing.T, scheme vercmp.Scheme, a, b string, want int) {
	t.Helper()
	got, ok := vercmp.Order(scheme, a, b)
	if !ok {
		t.Fatalf("%q against %q could not be ordered", a, b)
	}
	if got != want {
		t.Errorf("%q against %q is %d, want %d", a, b, got, want)
	}
	back, ok := vercmp.Order(scheme, b, a)
	if !ok {
		t.Fatalf("%q against %q could not be ordered", b, a)
	}
	if back != -want {
		t.Errorf("%q against %q is %d, and back again is %d — want %d", a, b, got, back, -want)
	}
}
