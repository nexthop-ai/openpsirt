package finding_test

import (
	"strings"
	"testing"
	"time"

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

func TestANoteWithNothingToSayIsNotWritten(t *testing.T) {
	// A heading over nothing is a question in the reader's mind about whether
	// something is missing, and a comparison that fixed nothing has no note.
	if notes := finding.Notes(about("2.4.0"), &finding.Comparison{
		Still: []finding.Changed{
			{Vulnerability: "CVE-2026-1", Component: "libnl", ArrivedFrom: "3.7.0"},
		},
	}); notes != "" {
		t.Errorf("a note was written for a release that fixed nothing:\n%s", notes)
	}
}
