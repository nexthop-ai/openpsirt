package finding_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAVectorIsScoredTheWayThePublishedFormulaScoresIt(t *testing.T) {
	// Each worked through the published formula by hand rather than taken from
	// this code, so it is checked against the scheme rather than against
	// itself. The scope-changed one is here because that is where the formula
	// stops being a product of independent weights, and where writing the
	// expected number from memory got it wrong by a tenth.
	for _, c := range []struct {
		vector string
		score  int
		band   string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 980, "critical"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", 910, "critical"},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 550, "medium"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 470, "medium"},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0, "none"},
		// The same base formula, so the older version scores identically.
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 980, "critical"},
	} {
		t.Run(c.vector, func(t *testing.T) {
			got, err := finding.Score(c.vector)
			if err != nil {
				t.Fatalf("scoring: %v", err)
			}
			if got.ScoreCenti != c.score {
				t.Errorf("scored %d, want %d", got.ScoreCenti, c.score)
			}
			if got.Severity != c.band {
				t.Errorf("banded as %q, want %q", got.Severity, c.band)
			}
		})
	}
}

func TestAVectorThisDoesNotUnderstandIsRefusedRatherThanScored(t *testing.T) {
	// A number that came out of the wrong formula looks exactly like every
	// other number here, and nothing downstream could tell.
	for _, c := range []struct{ what, vector string }{
		{"version 4, whose base formula is different", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"version 2, a different scheme entirely", "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{"a metric missing", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"},
		{"a value that metric does not take", "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"a metric given twice", "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"nonsense", "not a vector"},
	} {
		t.Run(c.what, func(t *testing.T) {
			if _, err := finding.Score(c.vector); err == nil {
				t.Errorf("%s was scored anyway", c.what)
			}
		})
	}
}

func TestNoVectorIsNotAScoreOfZero(t *testing.T) {
	// Early triage: somebody records what they have found before anybody has
	// worked out how bad it is. A zero would say "harmless", which is a
	// judgment nobody made.
	got, err := finding.Score("")
	if err != nil {
		t.Fatalf("an unstated vector answered %v", err)
	}
	if got != nil {
		t.Errorf("an unstated vector produced %+v, want nothing", got)
	}
}

func TestTheVectorIsKeptAsGivenApartFromItsCase(t *testing.T) {
	got, err := finding.Score("cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.Vector, "CVSS:3.1/") {
		t.Errorf("the vector came back as %q", got.Vector)
	}
}
