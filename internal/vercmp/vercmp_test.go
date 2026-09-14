package vercmp_test

import (
	"testing"

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
		// Ecosystems that plainly do have an ordering, and whose algorithm is
		// not written here. Claiming one is the confident wrong answer this
		// package exists to refuse.
		{"rpm", vercmp.Unordered},
		{"apk", vercmp.Unordered},
		{"pypi", vercmp.Unordered},
		{"maven", vercmp.Unordered},
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
	} {
		if _, ok := vercmp.Order(each.scheme, each.a, each.b); ok {
			t.Errorf("%q against %q was ordered, want a refusal", each.a, each.b)
		}
	}
}

func TestReachingAVersionReachesEveryEarlierOne(t *testing.T) {
	// What a picker asks. An issue fixed in an earlier release is closed by a
	// later one, and the kernel is the case that makes it matter: the newest
	// release names two of its own and carries every fix before it.
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
