// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"strings"
	"testing"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/text"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func about(to string) finding.Note {
	return finding.Note{To: to}
}

func TestAReleaseNoteCarriesOnlyWhatWasFixed(t *testing.T) {
	// The document goes to customers and they keep it, so a bump that
	// carried the issue with it must not be listed under fixes — and
	// neither must anything that is not a fix at all. What a build still
	// contains is a disposition, and the document for those is a VEX,
	// which a customer's own scanner reads and which does not drift from
	// prose nobody regenerates.
	notes := finding.Notes(about("2.4.0"), &finding.Comparison{
		Fixed: []finding.Changed{
			{Vulnerability: "CVE-2026-1", Component: "libnl", Severity: "high",
				Because: finding.Upgraded},
			{Vulnerability: "CVE-2026-2", Component: "zlib", Severity: "critical",
				Because: finding.Superseded},
			{Vulnerability: "CVE-2026-3", Component: "busybox", Severity: "low",
				Because: finding.Unexplained},
			{Vulnerability: "CVE-2026-4", Component: "curl", Severity: "high",
				Because: finding.Invalid},
		},
		Newly: []finding.Changed{
			{Vulnerability: "CVE-2026-5", Component: "openssl", Severity: "critical"},
		},
		Still: []finding.Changed{
			{Vulnerability: "CVE-2026-6", Component: "vim", Severity: "critical"},
		},
	})
	if !strings.Contains(notes, "CVE-2026-1") {
		t.Errorf("a real fix is missing:\n%s", notes)
	}
	// Everything else the comparison holds. A superseded bump and an
	// unexplained closure are not fixes; a withdrawn record was never
	// affected; and what is newly or still present is a statement about what
	// the build contains rather than about what was done.
	for _, absent := range []string{
		"CVE-2026-2", "CVE-2026-3", "CVE-2026-4", "CVE-2026-5", "CVE-2026-6",
	} {
		if strings.Contains(notes, absent) {
			t.Errorf("%s is in a note that carries only fixes:\n%s", absent, notes)
		}
	}
	for _, absent := range []string{"Newly present", "Still present", "Moved but not fixed"} {
		if strings.Contains(notes, absent) {
			t.Errorf("a %q section was written:\n%s", absent, notes)
		}
	}
}

func TestAFixSaysHowItWasFixed(t *testing.T) {
	// "Upgraded to 3.9.0" and "a carried patch" are different sentences to
	// whoever reads this, and the closure reason already tells them apart.
	notes := finding.Notes(about("2.4.0"), &finding.Comparison{
		Fixed: []finding.Changed{
			{Vulnerability: "CVE-2026-1", Component: "libnl", Because: finding.Upgraded,
				FromVersion: "3.7.0", MovedTo: "3.9.0"},
			{Vulnerability: "CVE-2026-2", Component: "openssl", Because: finding.Revised},
			{Vulnerability: "CVE-2026-3", Component: "telnetd", Because: finding.Removed},
		},
	})
	for _, want := range []string{
		"upgraded, 3.7.0 → 3.9.0", "carried patch", "no longer shipped",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("the note does not say %q:\n%s", want, notes)
		}
	}
}

func TestANoteSaysWhatItWasProducedAgainst(t *testing.T) {
	// A note somebody kept for a year is re-checkable only if it says which
	// two builds, when, and against what — a vulnerability database ships bad
	// data and is corrected, and "which data said so" is then the question.
	notes := finding.Notes(finding.Note{
		From: "v1.0 broadcom", To: "main broadcom",
		At:       time.Date(2026, 9, 5, 15, 28, 52, 0, time.UTC),
		Scanner:  "grype 0.100.0",
		Database: "2026-08-28",
	}, &finding.Comparison{
		Fixed: []finding.Changed{
			{Vulnerability: "CVE-2026-1", Component: "libnl", Because: finding.Upgraded},
		},
	})
	for _, want := range []string{
		"## Security fixes in main broadcom",
		"Comparing v1.0 broadcom with main broadcom",
		"last measured 2026-09-05",
		"grype 0.100.0",
		"vulnerability data of 2026-08-28",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("the note does not say %q:\n%s", want, notes)
		}
	}
}

func TestANoteSaysHowManyFixesItLeftOutAndNeverWhich(t *testing.T) {
	// Public findings only is the right default, and silently dropping the
	// count is not: a reader cannot otherwise tell a release that fixed
	// nothing undisclosed from one whose undisclosed fixes were taken off the
	// page. The number says nothing about any of them.
	notes := finding.Notes(finding.Note{To: "2.4.0", Omitted: 3}, &finding.Comparison{
		Fixed: []finding.Changed{
			{Vulnerability: "CVE-2026-1", Component: "libnl", Because: finding.Upgraded},
		},
	})
	if !strings.Contains(notes, "3 further fixes are not listed here") {
		t.Errorf("the note does not say what it left out:\n%s", notes)
	}

	one := finding.Notes(finding.Note{To: "2.4.0", Omitted: 1}, &finding.Comparison{})
	if !strings.Contains(one, "One further fix is not listed here") {
		t.Errorf("the note does not count one properly:\n%s", one)
	}

	none := finding.Notes(about("2.4.0"), &finding.Comparison{
		Fixed: []finding.Changed{
			{Vulnerability: "CVE-2026-1", Component: "libnl", Because: finding.Upgraded},
		},
	})
	if strings.Contains(none, "not listed here") {
		t.Errorf("a note with nothing left out said something was:\n%s", none)
	}
}

func TestTheSameComparisonRendersTheSameDocumentTwice(t *testing.T) {
	// A release note that reorders between reads is one nobody can diff, and
	// the map iteration underneath is not ordered.
	comparison := &finding.Comparison{
		Fixed: []finding.Changed{
			{Vulnerability: "CVE-2026-9", Component: "a", Severity: "low",
				Because: finding.Upgraded},
			{Vulnerability: "CVE-2026-1", Component: "b", Severity: "critical",
				Because: finding.Upgraded},
			{Vulnerability: "CVE-2026-5", Component: "c", Severity: "critical",
				Because: finding.Upgraded},
		},
	}
	first := finding.Notes(about("2.4.0"), comparison)
	for range 5 {
		if again := finding.Notes(about("2.4.0"), comparison); again != first {
			t.Fatalf("the document changed between runs:\n%s\n---\n%s", first, again)
		}
	}
	// Worst first, so somebody reading from the top reads the worst first.
	if strings.Index(first, "CVE-2026-1") > strings.Index(first, "CVE-2026-9") {
		t.Errorf("a low is listed above a critical:\n%s", first)
	}
}

func TestAReleaseThatFixedNothingSaysSo(t *testing.T) {
	// An empty answer cannot be told from a truncated response, from the
	// wrong pair of builds or from a request that went astray — every one of
	// which is also zero bytes.
	//
	// A heading over nothing is still a question in a reader's mind about
	// whether something is missing, which is why what comes back is a
	// sentence rather than an empty section.
	notes := finding.Notes(finding.Note{From: "2.3.0", To: "2.4.0"}, &finding.Comparison{
		Still: []finding.Changed{
			{Vulnerability: "CVE-2026-1", Component: "libnl", ArrivedFrom: "3.7.0"},
		},
	})
	if notes == "" {
		t.Fatal("a release that fixed nothing answered with nothing at all")
	}
	if strings.Contains(notes, "#") {
		t.Errorf("a release that fixed nothing was given a heading:\n%s", notes)
	}
	for _, want := range []string{"No security fixes", "2.4.0", "2.3.0"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the note does not say %q:\n%s", want, notes)
		}
	}
	// And what is still present is not in it, which is the rule the document
	// is written to whatever it says.
	if strings.Contains(notes, "CVE-2026-1") {
		t.Errorf("a finding that was not fixed is in the note:\n%s", notes)
	}
}

func TestEveryClosureThatCountsAsAFixHasWordsForIt(t *testing.T) {
	// One list rather than three projections of it. A closure the release
	// note keeps and the remediation rate does not count renders with nothing
	// after it, and two screens disagree about the same constant.
	if len(finding.Resolving()) == 0 {
		t.Fatal("nothing counts as a fix, so this checked nothing")
	}
	for _, each := range finding.Resolving() {
		if !each.Resolves() {
			t.Errorf("%q is in the list and does not read as resolving", each)
		}
		if finding.FixedBecause(each) == "" {
			t.Errorf("%q counts as a fix and the note has no words for it, so a reader "+
				"gets the issue and the component with nothing after it", each)
		}
	}
	// And the three that are not fixes stay out on both surfaces.
	for _, each := range []finding.Closure{
		finding.Invalid, finding.Superseded, finding.Unexplained,
	} {
		if each.Resolves() {
			t.Errorf("%q reads as an issue going away", each)
		}
	}
}

func TestOneUpgradeIsStatedOnceHoweverManyIssuesItClosed(t *testing.T) {
	// A kernel bump closes 917 issues in one move. Written one bullet per
	// issue, the same version pair is repeated 917 times in a document going
	// to a customer, and the thing they are looking for — what to move to —
	// is the part that repeats.
	var fixed []finding.Changed
	for _, cve := range []string{"CVE-2026-3", "CVE-2026-1", "CVE-2026-2"} {
		fixed = append(fixed, finding.Changed{
			Vulnerability: cve, Component: "linux", Severity: "high",
			Because: finding.Upgraded, FromVersion: "6.12.41-1", MovedTo: "6.12.85-1",
		})
	}
	notes := finding.Notes(about("2.4.0"), &finding.Comparison{Fixed: fixed})

	if n := strings.Count(notes, "6.12.41-1 → 6.12.85-1"); n != 1 {
		t.Errorf("the upgrade is stated %d times rather than once:\n%s", n, notes)
	}
	for _, want := range []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the note lost %s while grouping:\n%s", want, notes)
		}
	}
	// Under the upgrade, not beside it: a reader has to be able to tell which
	// move answers which advisory.
	if strings.Index(notes, "6.12.85-1") > strings.Index(notes, "CVE-2026-1") {
		t.Errorf("the issues are listed above the move that closed them:\n%s", notes)
	}
}

func TestTwoMovesOfOneComponentStayApart(t *testing.T) {
	// Two upgrades of the same component in one comparison are two different
	// answers to "what do I move to". Folded onto the component alone, one of
	// them would be stated over both.
	notes := finding.Notes(about("2.4.0"), &finding.Comparison{
		Fixed: []finding.Changed{
			{Vulnerability: "CVE-2026-1", Component: "linux", Severity: "high",
				Because: finding.Upgraded, FromVersion: "6.12.41-1", MovedTo: "6.12.85-1"},
			{Vulnerability: "CVE-2026-2", Component: "linux", Severity: "high",
				Because: finding.Upgraded, FromVersion: "5.10.1-1", MovedTo: "5.10.9-1"},
			{Vulnerability: "CVE-2026-3", Component: "linux", Severity: "high",
				Because: finding.Revised},
		},
	})
	for _, want := range []string{
		"6.12.41-1 → 6.12.85-1", "5.10.1-1 → 5.10.9-1", "carried patch",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("the note does not say %q:\n%s", want, notes)
		}
	}
	if n := strings.Count(notes, "- linux"); n != 3 {
		t.Errorf("three moves of one component made %d entries:\n%s", n, notes)
	}
}

func TestABulletCarriesWhatDecidesWhenTheUpgradeIsTaken(t *testing.T) {
	// A name and a word are not enough to act on. The number, whether
	// somebody is known to be exploiting it, and where it is written up are
	// all held and none of them reached the document a customer reads.
	notes := finding.Notes(about("2.4.0"), &finding.Comparison{
		Fixed: []finding.Changed{
			{
				Vulnerability: "CVE-2026-1", Component: "linux-image", Severity: "critical",
				Because: finding.Upgraded, FromVersion: "6.12.41-1", MovedTo: "6.12.85-1",
				ScoreCenti: 980, Exploited: true,
				Advisory: "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
			},
			{
				Vulnerability: "CVE-2026-2", Component: "linux-image", Severity: "low",
				Because: finding.Upgraded, FromVersion: "6.12.41-1", MovedTo: "6.12.85-1",
				// An address a reader's machine would act on, from a feed.
				// The same rule an address stored beside a claim goes
				// through, and this one leaves the building.
				Advisory: "ms-msdt:calc",
			},
			{
				Vulnerability: "CVE-2026-3", Component: "linux-image", Severity: "low",
				Because: finding.Upgraded, FromVersion: "6.12.41-1", MovedTo: "6.12.85-1",
				// A scheme nothing refuses, carrying a newline. Inside angle
				// brackets the address ends at the first space, so the rest
				// of it is not a link — it is markdown, in a document going
				// to a customer.
				Advisory: "https://example.test/x\n\n## Fixed upstream\n- nothing",
			},
		},
	})
	if !strings.Contains(notes, "CVE-2026-1 (critical, 9.8, known exploited)") {
		t.Errorf("the bullet does not carry what decides when to take it:\n%s", notes)
	}
	if !strings.Contains(notes, "<https://nvd.nist.gov/vuln/detail/CVE-2026-1>") {
		t.Errorf("the bullet does not link the write-up:\n%s", notes)
	}
	if strings.Contains(notes, "ms-msdt") {
		t.Errorf("a scheme a machine acts on reached a published document:\n%s", notes)
	}
	// An issue nobody scored says the word and no number, rather than a zero
	// that reads as harmless.
	if !strings.Contains(notes, "CVE-2026-2 (low)") {
		t.Errorf("an unscored issue does not read as unscored:\n%s", notes)
	}
	// And an address that would close the autolink is left out rather than
	// printed: what follows it is whole markdown lines a feed chose.
	if strings.Contains(notes, "Fixed upstream") {
		t.Errorf("a feed wrote lines into a published note:\n%s", notes)
	}
}

func TestNothingAThirdPartyNamedBecomesMarkupInANote(t *testing.T) {
	// A component name, a version and an identifier are chosen upstream, and
	// the note goes to a customer's markdown viewer. Each is text there: no
	// link, image, markup, heading or list the name opened.
	link := "[Download the fix](https://evil.example/p)"
	image := "<img src=https://evil.example/t.gif>"
	notes := finding.Notes(finding.Note{
		From: "# v1 " + link, To: "main " + image,
		Scanner: "grype ![x](https://evil.example/s)", Database: "https://evil.example/d",
	}, &finding.Comparison{
		Fixed: []finding.Changed{{
			Vulnerability: "CVE-2026-1 " + link, Component: "- " + image + "\n\n## Fixed",
			Severity: "high <b>x</b>", Because: finding.Upgraded,
			FromVersion: "1.0 ![x](https://evil.example/f)", MovedTo: "www.evil.example",
			Advisory: "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
		}},
	})

	source := []byte(notes)
	document := goldmark.New(goldmark.WithExtensions(extension.GFM)).Parser().
		Parse(text.NewReader(source))
	headings, walked := 0, 0
	_ = ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		walked++
		switch typed := node.(type) {
		case *ast.Heading:
			headings++
		case *ast.AutoLink:
			// The write-up the note links on purpose, and nothing else.
			if got := string(typed.URL(source)); got != "https://nvd.nist.gov/vuln/detail/CVE-2026-1" {
				t.Errorf("%q became a link:\n%s", got, notes)
			}
		case *ast.Link, *ast.Image, *ast.RawHTML, *ast.HTMLBlock:
			t.Errorf("a third party's text became %s:\n%s", node.Kind(), notes)
		}
		return ast.WalkContinue, nil
	})
	if walked == 0 {
		t.Fatal("the note parsed to nothing, so this checked nothing")
	}
	if headings != 1 {
		t.Errorf("the note has %d headings, want its own one:\n%s", headings, notes)
	}
}
