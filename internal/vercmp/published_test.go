package vercmp_test

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// The two suites below are the projects' own, committed verbatim under
// testdata: rpm's from rpm-software-management/rpm, tests/rpmvercmp.at, and
// Alpine's from alpine/apk-tools, test/unit/version.data. testdata/README.md
// records where each came from and the two places this answers differently. Transcribing an ordering by hand is how a scheme ends up
// confidently wrong about a pair nobody thought to try, and each of these
// carries the pairs its maintainers found worth pinning.

var rpmVector = regexp.MustCompile(`RPMVERCMP\(([^,]*),\s*([^,]*),\s*(-?\d+)\)`)

func TestRPMOrdersWhatItsOwnSuiteSaysItShould(t *testing.T) {
	body, err := os.ReadFile("testdata/rpmvercmp.at")
	if err != nil {
		t.Fatal(err)
	}
	found := rpmVector.FindAllStringSubmatch(string(body), -1)
	if len(found) == 0 {
		t.Fatal("no vectors were read from the suite, so this checked nothing")
	}
	ordered := 0
	for _, one := range found {
		a, b := one[1], one[2]
		want, err := strconv.Atoi(one[3])
		if err != nil {
			t.Fatalf("vector %q against %q states %q as its answer", a, b, one[3])
		}
		got, ok := vercmp.Order(vercmp.RPM, a, b)
		if !ok {
			// rpm orders any two strings; this refuses what is not a version.
			// So a refusal is only right where one of them is not one, asked
			// here by a rule of its own rather than by calling the same code
			// the answer came from.
			if versionish(a) && versionish(b) {
				t.Errorf("%q against %q was refused, and both are versions", a, b)
			}
			continue
		}
		ordered++
		if got != want {
			t.Errorf("%q against %q is %d, want %d", a, b, got, want)
		}
	}
	// A suite this refused wholesale would pass every assertion above.
	if ordered < 70 {
		t.Errorf("only %d of %d vectors were ordered at all", ordered, len(found))
	}
}

// versionish is a second opinion on whether a string is a version, written
// plainly so that a refusal is checked against something other than the code
// that produced it: it begins with a digit and holds only bytes a version may.
func versionish(v string) bool {
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c == '.', c == '_', c == '+', c == '~', c == '^', c == '-', c == ':':
		default:
			return false
		}
	}
	return true
}

func TestAPKOrdersWhatItsOwnSuiteSaysItShould(t *testing.T) {
	ordered := 0
	eachAPKLine(t, func(t *testing.T, line string) {
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return
		}
		a, op, b := parts[0], parts[1], parts[2]
		want, comparison := map[string]int{"<": -1, "=": 0, ">": 1}[op]
		if !comparison {
			// The tilde operators ask whether one version is within another's
			// series, which is a different question from which of two is
			// further along.
			return
		}
		got, ok := vercmp.Order(vercmp.APK, a, b)
		if !ok {
			// Alpine falls back to sorting the text where a version does not
			// read; this refuses instead, so a refusal is right only where one
			// of them is not a version.
			if apkReads(a) && apkReads(b) {
				t.Errorf("%q against %q was refused, and both read as versions", a, b)
			}
			return
		}
		ordered++
		if got != want {
			t.Errorf("%q %s %q is %d, want %d", a, op, b, got, want)
		}
	})
	if ordered < 600 {
		t.Errorf("only %d vectors were ordered at all", ordered)
	}
}

func TestAPKReadsExactlyTheVersionsItsOwnSuiteCallsValid(t *testing.T) {
	// The tail of the suite is a validity list rather than an ordering one:
	// a bare line is a version that reads, and one marked with "!" is a string
	// that does not. It is the half that says the refusal is deliberate.
	valid, invalid := 0, 0
	eachAPKLine(t, func(t *testing.T, line string) {
		if len(strings.Fields(line)) != 1 {
			return
		}
		want := !strings.HasPrefix(line, "!")
		v := strings.TrimPrefix(line, "!")
		// Ordered against itself, which is the only way to ask this through
		// what the package offers: a version that reads compares equal to
		// itself, and one that does not is refused.
		_, ok := vercmp.Order(vercmp.APK, v, v)
		if ok != want {
			if want {
				t.Errorf("%q was refused, and the suite calls it a version", v)
			} else {
				t.Errorf("%q was ordered, and the suite calls it invalid", v)
			}
		}
		if want {
			valid++
		} else {
			invalid++
		}
	})
	if valid == 0 || invalid == 0 {
		t.Fatalf("the suite gave %d valid and %d invalid versions, so this "+
			"checked only one direction", valid, invalid)
	}
}

// apkReads is a second opinion on whether Alpine would read a string as a
// version, for the same reason versionish exists: a refusal checked by the code
// that refused proves nothing.
//
// Two rules, which is what the suite's invalid entries are almost all about:
// the numbers carry at most one letter, and a named suffix is one of the names.
func apkReads(v string) bool {
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	body := v
	if at := strings.IndexAny(body, "_~-"); at >= 0 {
		body = body[:at]
	}
	letters := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= '0' && c <= '9', c == '.':
		case c >= 'a' && c <= 'z':
			letters++
		default:
			return false
		}
	}
	if letters > 1 {
		return false
	}
	for _, part := range strings.Split(v, "_")[1:] {
		name := strings.TrimRight(part, "0123456789")
		switch name {
		case "alpha", "beta", "pre", "rc", "cvs", "svn", "git", "hg", "p":
		default:
			return false
		}
	}
	return true
}

// eachAPKLine walks the suite, skipping blanks and comments.
func eachAPKLine(t *testing.T, fn func(t *testing.T, line string)) {
	t.Helper()
	file, err := os.Open("testdata/apk-version.data")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	lines := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if at := strings.Index(line, "#"); at >= 0 {
			line = line[:at]
		}
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		lines++
		fn(t, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if lines == 0 {
		t.Fatal("the suite is empty, so this checked nothing")
	}
}

func TestTheNewSchemesOrderBothWaysRoundAcrossTheirWholeSuites(t *testing.T) {
	// A comparator read as a comparator rather than as a table of answers. A
	// rule returning the same sign both ways is not one wrong answer, it is a
	// broken ordering: a list sorted with it depends on the order it was
	// already in, which is a bug no single vector shows.
	checked := 0
	mirror := func(t *testing.T, scheme vercmp.Scheme, a, b string) {
		t.Helper()
		forward, ok := vercmp.Order(scheme, a, b)
		if !ok {
			return
		}
		back, ok := vercmp.Order(scheme, b, a)
		if !ok {
			t.Errorf("%q against %q ordered, and %q against %q did not", a, b, b, a)
			return
		}
		checked++
		if forward != -back {
			t.Errorf("%q against %q is %d, and back again is %d", a, b, forward, back)
		}
	}

	body, err := os.ReadFile("testdata/rpmvercmp.at")
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range rpmVector.FindAllStringSubmatch(string(body), -1) {
		mirror(t, vercmp.RPM, one[1], one[2])
	}
	eachAPKLine(t, func(t *testing.T, line string) {
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return
		}
		mirror(t, vercmp.APK, parts[0], parts[2])
	})
	if checked < 600 {
		t.Errorf("only %d pairs were ordered both ways", checked)
	}
}
