package scanner_test

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
)

func parse(t *testing.T) scanner.Result {
	t.Helper()
	f, err := os.OpenInRoot("testdata", "grype-output.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	result, err := scanner.ParseGrype(f, scanner.Limits{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return result
}

func TestWhatRanAndAgainstWhatIsRecorded(t *testing.T) {
	// A finding that appeared or vanished because the scanner or its data
	// moved is unexplainable without this.
	result := parse(t)
	if result.Version != "0.112.0" {
		t.Errorf("scanner version reads as %q", result.Version)
	}
	if result.DatabaseVersion != "2026-08-28T09:21:39Z" {
		t.Errorf("database version reads as %q", result.DatabaseVersion)
	}
}

func TestTheDatabaseVersionIsFoundWhereverItSits(t *testing.T) {
	// Where the database describes itself moved between versions of the
	// scanner. An operator running an older build should not silently lose the
	// record of what their findings were matched against.
	older := `{"matches": [], "descriptor": {"name": "grype", "version": "0.90.0",
	 "db": {"built": "2026-01-01T00:00:00Z", "schemaVersion": 5}}}`
	result, err := scanner.ParseGrype(strings.NewReader(older), scanner.Limits{})
	if err != nil {
		t.Fatalf("an older scanner's output: %v", err)
	}
	if result.DatabaseVersion != "2026-01-01T00:00:00Z" {
		t.Errorf("database version reads as %q", result.DatabaseVersion)
	}
}

func TestEveryMatchBecomesAReportedIssue(t *testing.T) {
	result := parse(t)
	if len(result.Reported) != 7 {
		t.Fatalf("read %d matches, want 7", len(result.Reported))
	}
	for _, r := range result.Reported {
		if r.Issue.Identifier == "" {
			t.Error("an issue was read with no identifier")
		}
		if r.Component.Name == "" || r.Component.Version == "" {
			t.Errorf("an issue was read against %+v", r.Component)
		}
		if r.Component.Purl == "" {
			t.Error("a package identifier was dropped, and it is what matches this back to what we hold")
		}
	}
}

func TestTheOtherNamesForAnIssueAreCarried(t *testing.T) {
	// The scanner files many issues under an advisory identifier and knows the
	// national one alongside. Dropping the alias would make it a second issue
	// the first time another scanner reported it the other way round.
	var withAliases int
	for _, r := range parse(t).Reported {
		if len(r.Issue.Aliases) == 0 {
			continue
		}
		withAliases++
		for _, alias := range r.Issue.Aliases {
			if alias == r.Issue.Identifier {
				t.Error("an issue lists itself as one of its other names")
			}
		}
	}
	if withAliases == 0 {
		t.Fatal("no aliases were read from output that carries them")
	}
}

func TestTheThreeFixStatesAreToldApart(t *testing.T) {
	// "No fix exists yet" and "upstream will not fix this" are different
	// situations, and the second changes the outcome somebody should reach.
	seen := map[finding.FixState]int{}
	for _, r := range parse(t).Reported {
		seen[r.FixState]++
		if r.FixState == finding.FixedUpstream && r.FixedIn == "" {
			t.Errorf("%s is fixed upstream with no version to move to", r.Component.Name)
		}
	}
	for _, state := range []finding.FixState{finding.FixedUpstream, finding.NoFix, finding.WontFix} {
		if seen[state] == 0 {
			t.Errorf("no issue read as %q, and the recorded output has one", state)
		}
	}
}

func TestSeverityIsAWordInOneCase(t *testing.T) {
	// The scanner capitalizes them and two spellings of one severity would
	// sort and group as two.
	var rated int
	for _, r := range parse(t).Reported {
		if r.Issue.Severity == "" {
			continue
		}
		rated++
		if r.Issue.Severity != strings.ToLower(r.Issue.Severity) {
			t.Errorf("%s is rated %q", r.Component.Name, r.Issue.Severity)
		}
	}
	if rated == 0 {
		t.Fatal("nothing was rated, and the recorded output rates everything")
	}
}

func TestOutputThatIsNotUnderstoodIsRefused(t *testing.T) {
	if _, err := scanner.ParseGrype(strings.NewReader("not json"), scanner.Limits{}); err == nil {
		t.Error("unreadable scanner output was accepted")
	}
}

func TestAnEmptyRunIsNotAFailure(t *testing.T) {
	// Nothing found is an ordinary answer, and treating it as an error would
	// make a clean product look like a broken scanner.
	result, err := scanner.ParseGrype(strings.NewReader(
		`{"matches": [], "descriptor": {"name": "grype", "version": "0.112.0"}}`),
		scanner.Limits{})
	if err != nil {
		t.Fatalf("an empty run: %v", err)
	}
	if len(result.Reported) != 0 {
		t.Errorf("read %d issues from an empty run", len(result.Reported))
	}
}

func TestHowGrypeReachedAMatchIsRead(t *testing.T) {
	// The scanner tries advisory data for the package's own ecosystem first
	// and falls back to comparing a published identifier against an upstream
	// version range. On a distribution's package those two mean very
	// different things, and the output says which happened.
	//
	// The real shape, from a scan of an Alpine image: an apk package whose
	// only match detail is a cpe-match, with no fix information at all.
	const output = `{
	  "matches": [
	    {
	      "vulnerability": {"id": "CVE-2025-60876", "severity": "Medium",
	        "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2025-60876",
	        "fix": {"state": "", "versions": []}},
	      "artifact": {"name": "busybox", "version": "1.37.0-r14",
	        "purl": "pkg:apk/alpine/busybox@1.37.0-r14?distro=alpine-3.21.7"},
	      "matchDetails": [{"type": "cpe-match"}]
	    },
	    {
	      "vulnerability": {"id": "CVE-2026-1234", "severity": "High",
	        "dataSource": "https://secdb.alpinelinux.org/",
	        "fix": {"state": "fixed", "versions": ["1.37.0-r15"]}},
	      "artifact": {"name": "curl", "version": "8.11.0-r2",
	        "purl": "pkg:apk/alpine/curl@8.11.0-r2?distro=alpine-3.21.7"},
	      "matchDetails": [{"type": "exact-direct-match"}]
	    },
	    {
	      "vulnerability": {"id": "CVE-2026-9999", "severity": "Low",
	        "dataSource": "https://example.test/"},
	      "artifact": {"name": "mystery", "version": "1.0"},
	      "matchDetails": []
	    }
	  ],
	  "descriptor": {"name": "grype", "version": "0.118.0"}
	}`

	result, err := scanner.ParseGrype(strings.NewReader(output), scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Reported) != 3 {
		t.Fatalf("%d reported, want 3", len(result.Reported))
	}
	how := map[string]finding.Reported{}
	for _, r := range result.Reported {
		how[r.Component.Name] = r
	}

	// Compared against an upstream range. A distribution that backported the
	// fix looks the same as one that did not, which is what makes this the
	// question worth surfacing.
	if got := how["busybox"].Matched; got != finding.ByIdentifier {
		t.Errorf("a cpe-match reads as %q, want it marked as reached by identifier", got)
	}
	if got := how["busybox"].MatchedFrom; got != "https://nvd.nist.gov/vuln/detail/CVE-2025-60876" {
		t.Errorf("the match came from %q", got)
	}

	// The people who package it said so, and what they say about a fix is
	// about the version actually installed.
	if got := how["curl"].Matched; got != finding.ByAdvisory {
		t.Errorf("an exact match against advisory data reads as %q", got)
	}

	// Nothing said. Left empty rather than guessed: a word this does not know
	// is a word whose strength nobody has checked.
	if got := how["mystery"].Matched; got != "" {
		t.Errorf("a match with no details reads as %q, want nothing claimed", got)
	}
}

func TestAnUnknownMatchKindIsTreatedAsTheWeakerOne(t *testing.T) {
	// A scanner adding a match kind we have not seen must not have it read as
	// "the people who package this confirmed it". Unrecognized is the
	// direction that hides something, so it goes the other way.
	const output = `{
	  "matches": [{
	    "vulnerability": {"id": "CVE-2026-1", "severity": "High"},
	    "artifact": {"name": "thing", "version": "1.0"},
	    "matchDetails": [{"type": "exact-direct-match"}, {"type": "cpe-match"}]
	  }],
	  "descriptor": {"name": "grype", "version": "0.118.0"}
	}`
	result, err := scanner.ParseGrype(strings.NewReader(output), scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Reported[0].Matched; got != finding.ByIdentifier {
		t.Errorf("a match reached both ways reads as %q, want the weaker of the two", got)
	}

	// The kind this test is named for: a word the reader does not recognize,
	// with no CPE detail beside it to decide the answer first. The two details
	// above are both recognized, so neither of them reaches this arm.
	const unknown = `{
	  "matches": [{
	    "vulnerability": {"id": "CVE-2026-2", "severity": "High"},
	    "artifact": {"name": "thing", "version": "1.0"},
	    "matchDetails": [{"type": "future-fuzzy-match"}]
	  }],
	  "descriptor": {"name": "grype", "version": "0.118.0"}
	}`
	fuzzy, err := scanner.ParseGrype(strings.NewReader(unknown), scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := fuzzy.Reported[0].Matched; got != finding.ByIdentifier {
		t.Errorf("a match kind nobody here has checked reads as %q, want the weaker of "+
			"the two — unrecognized is the direction that hides something", got)
	}
}

func TestTheRangeAMatchFiredOnAndTheDataThatAnsweredAreKept(t *testing.T) {
	// The match kind says a distribution's package was reached by
	// comparing an upstream range, which is the judgment somebody has to
	// make. These two are the evidence for it: the range itself, which
	// names no packaging revision, and which body of data answered, which
	// is finer than the two words the kind records.
	//
	// Both are the scanner's own words, kept and never parsed. Deciding
	// whether a version falls inside a range needs an ordering per
	// ecosystem, which is a different project.
	const doc = `{"matches":[{
	  "vulnerability":{"id":"CVE-2025-60876","severity":"Medium",
	    "namespace":"nvd:cpe",
	    "dataSource":"https://nvd.nist.gov/vuln/detail/CVE-2025-60876"},
	  "artifact":{"name":"busybox-binsh","version":"1.37.0-r31",
	    "purl":"pkg:apk/alpine/busybox-binsh@1.37.0-r31?distro=alpine-3.24.1"},
	  "matchDetails":[{"type":"cpe-match","found":{"versionConstraint":"<= 1.37.0 (unknown)"}}]
	}]}`

	result, err := scanner.ParseGrype(strings.NewReader(doc), scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Reported) != 1 {
		t.Fatalf("%d findings reported", len(result.Reported))
	}
	got := result.Reported[0]
	if got.MatchedRange != "<= 1.37.0 (unknown)" {
		t.Errorf("the range it fired on reads %q", got.MatchedRange)
	}
	if got.MatchedIn != "nvd:cpe" {
		t.Errorf("what answered reads %q", got.MatchedIn)
	}
	// And the range is the one the kind is about: an upstream range against a
	// version carrying a packaging revision the range never mentions.
	if got.Matched != finding.ByIdentifier {
		t.Errorf("reached %q, want the identifier match this range describes", got.Matched)
	}
}

func TestAMatchThatStatesNoRangeSaysSoRatherThanGuessing(t *testing.T) {
	// A scanner reporting no range is not the same as one reporting an empty
	// range, and neither is something to fill in.
	const doc = `{"matches":[{
	  "vulnerability":{"id":"CVE-2026-1","severity":"High"},
	  "artifact":{"name":"libfoo","version":"1.0","purl":"pkg:deb/debian/libfoo@1.0"},
	  "matchDetails":[{"type":"exact-direct-match"}]
	}]}`

	result, err := scanner.ParseGrype(strings.NewReader(doc), scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Reported[0]; got.MatchedRange != "" || got.MatchedIn != "" {
		t.Errorf("invented range %q from %q", got.MatchedRange, got.MatchedIn)
	}
}

func TestTheRangeComesFromTheDetailTheKindWasDecidedBy(t *testing.T) {
	// A match often carries two details: an advisory for the package's own
	// ecosystem, and a comparison against an upstream range. The kind is
	// decided by whether any of them compared an identifier, so the range has
	// to come from that same one — otherwise a finding reads "not confirmed
	// by a packager" beside a range that names the packaging revision, and
	// the two halves of the evidence argue with each other.
	const doc = `{"matches":[{
	  "vulnerability":{"id":"CVE-2025-1000","severity":"High","namespace":"nvd:cpe"},
	  "artifact":{"name":"busybox","version":"1.37.0-r31",
	    "purl":"pkg:apk/alpine/busybox@1.37.0-r31?distro=alpine-3.24.1"},
	  "matchDetails":[
	    {"type":"exact-direct-match","found":{"versionConstraint":"< 1.37.0-r15"}},
	    {"type":"cpe-match","found":{"versionConstraint":"<= 1.37.0 (unknown)"}}
	  ]
	}]}`

	result, err := scanner.ParseGrype(strings.NewReader(doc), scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	got := result.Reported[0]
	if got.Matched != finding.ByIdentifier {
		t.Fatalf("reached %q, want the identifier match the cpe detail describes", got.Matched)
	}
	if got.MatchedRange != "<= 1.37.0 (unknown)" {
		t.Errorf("the range reads %q, which is the other detail's — so the evidence "+
			"names a packaging revision beside a verdict saying packaging was not considered",
			got.MatchedRange)
	}
}

func TestPatchesOnTheRelatedRecordAreKept(t *testing.T) {
	// A match against a distribution's package resolves to that
	// distribution's record, which points at its own tracker and nothing
	// else. The commits that carry the fix are on the upstream record, which
	// the scanner reports alongside as a related vulnerability — and this
	// read only the identifier off those, so it parsed the addresses and
	// discarded them. A kernel CVE listing eight git.kernel.org commits
	// showed one tracker link and no patches at all.
	var patches int
	for _, r := range parse(t).Reported {
		for _, ref := range r.Issue.References {
			if ref.Kind == finding.Patch {
				patches++
			}
		}
	}
	if patches == 0 {
		t.Fatal("no patch reference survived output whose related records carry six of them")
	}

	// Specifically one that exists **only** on the related record. The
	// matched record for this issue carries none of the OpenSSL commits; its
	// related record carries four, which is the whole shape this is about.
	var here []string
	for _, r := range parse(t).Reported {
		if r.Issue.Identifier != "CVE-2024-6119" {
			continue
		}
		for _, ref := range r.Issue.References {
			here = append(here, ref.URL)
		}
	}
	if len(here) == 0 {
		t.Fatal("the issue whose related record carries the patches has no references")
	}
	if !slices.ContainsFunc(here, func(url string) bool {
		return strings.Contains(url, "github.com/openssl/openssl/commit/")
	}) {
		t.Error("a commit that is only on the related record did not survive")
	}
	// And nothing is listed twice: the two records overlap heavily.
	seen := map[string]bool{}
	for _, url := range here {
		if seen[url] {
			t.Errorf("reference listed twice: %s", url)
		}
		seen[url] = true
	}
}

// reportOf builds a report stating count matches, each naming one component.
func reportOf(count int) string {
	var doc strings.Builder
	doc.WriteString(`{"matches":[`)
	for i := range count {
		if i > 0 {
			doc.WriteString(",")
		}
		fmt.Fprintf(&doc, `{"vulnerability":{"id":"CVE-2026-%d"},`+
			`"artifact":{"name":"openssl","version":"3.0.1"}}`, i)
	}
	doc.WriteString(`],"descriptor":{"version":"0.112.0"}}`)
	return doc.String()
}

func TestAReportStatingMoreMatchesThanTheLimitIsRefused(t *testing.T) {
	// A report is components × matches × references and the producer controls
	// the first factor by uploading a scan file, so nothing bounds the
	// product unless this does. The pair is what catches a bound set too low:
	// exactly the limit is read, one past it is refused.
	limits := scanner.Limits{MaxMatches: 4}
	if _, err := scanner.ParseGrype(strings.NewReader(reportOf(4)), limits); err != nil {
		t.Fatalf("a report of exactly the limit: %v", err)
	}
	_, err := scanner.ParseGrype(strings.NewReader(reportOf(5)), limits)
	if err == nil {
		t.Fatal("a report past the match limit was read")
	}
	if !strings.Contains(err.Error(), "match limit") {
		t.Errorf("the refusal does not name the limit it hit: %v", err)
	}
}

// pointingAt builds a report of one match pointing at count addresses.
func pointingAt(count int) string {
	urls := make([]string, 0, count)
	for i := range count {
		urls = append(urls, fmt.Sprintf(`"https://example.test/%d"`, i))
	}
	return `{"matches":[{"vulnerability":{"id":"CVE-2026-1","urls":[` +
		strings.Join(urls, ",") + `]},"artifact":{"name":"openssl","version":"3.0.1"}}],` +
		`"descriptor":{"version":"0.112.0"}}`
}

func TestOneMatchPointingPastTheReferenceLimitIsRefused(t *testing.T) {
	// Bounded per match rather than per report, because the two multiply: a
	// report well inside the match limit is still a report of one match
	// pointing at everything.
	limits := scanner.Limits{MaxReferences: 4}
	if _, err := scanner.ParseGrype(strings.NewReader(pointingAt(4)), limits); err != nil {
		t.Fatalf("a match pointing at exactly the limit: %v", err)
	}
	_, err := scanner.ParseGrype(strings.NewReader(pointingAt(5)), limits)
	if err == nil {
		t.Fatal("a match past the reference limit was read")
	}
	if !strings.Contains(err.Error(), "reference limit") {
		t.Errorf("the refusal does not name the limit it hit: %v", err)
	}
}

func TestWhatLabelsAReferenceIsItsHostAndItsPath(t *testing.T) {
	// The label is what somebody sorts a dozen links by, and the function is
	// written to err toward saying less. Matched against the raw address a
	// query string, a fragment and a lookalike host all decided it, which is
	// the other direction.
	for _, c := range []struct {
		address string
		want    finding.ReferenceKind
	}{
		{"https://git.kernel.org/torvalds/c/abcdef", finding.Patch},
		{"https://patchwork.freedesktop.org/patch/1234/", finding.Patch},
		{"https://github.test/openssl/openssl/commit/abcdef", finding.Patch},
		{"https://nvd.nist.gov/vuln/detail/CVE-2026-1", finding.AdvisoryRef},
		{"https://github.test/openssl/openssl/security/advisories/GHSA-1", finding.AdvisoryRef},
		{"https://unrelated.test/thread/12", finding.Report},

		// A host somebody else controls that merely contains a name we
		// recognize. The expression matched a substring of the host.
		{"https://git.kernel.org.evil.test/", finding.Report},
		{"https://nvd.nist.gov.evil.test/", finding.Report},
		// A query string and a fragment are not the address's path.
		{"https://unrelated.test/?from=git.kernel.org", finding.Report},
		{"https://unrelated.test/#CVE-2026-1", finding.Report},
		{"https://unrelated.test/?ref=/commit/abcdef", finding.Report},
	} {
		got := scanner.KindOf(c.address)
		if got != c.want {
			t.Errorf("%s is labelled %q, want %q", c.address, got, c.want)
		}
	}
}
