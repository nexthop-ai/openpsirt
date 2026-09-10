package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestWhatIsBeingExploitedComesFirst(t *testing.T) {
	// The one that has to hold whatever else is true. Something being used
	// against people is the difference between a risk and an incident, and no
	// combination of the other three may outrank it.
	exploited := finding.Ranked{Exploited: true}
	for _, other := range []finding.Ranked{
		{Shipped: true, LikelihoodPPM: 1_000_000, ScoreCenti: 1000},
		{Shipped: true, ScoreCenti: 1000},
		{LikelihoodPPM: 1_000_000},
	} {
		if exploited.Rank() <= other.Rank() {
			t.Errorf("a known-exploited finding ranked at or below %+v", other)
		}
	}
}

func TestWhatReachesCustomersOutranksWhatDoesNot(t *testing.T) {
	// A critical in something only the build system runs matters less than a
	// medium in what people install.
	shipped := finding.Ranked{Shipped: true, ScoreCenti: 550}
	internal := finding.Ranked{ScoreCenti: 1000, LikelihoodPPM: 1_000_000}
	if shipped.Rank() <= internal.Rank() {
		t.Error("a medium that ships ranked below a critical that does not")
	}
}

func TestTheOrderWithinABandIsSeverityThenLikelihood(t *testing.T) {
	// This asserted the reverse, and the reverse was measured wrong on a real
	// image: 95% of its issues sat inside one order of magnitude of
	// likelihood, so letting that reorder severities moved things on
	// differences nobody should act on — while a 2004 negligible with no score
	// outranked every critical on a likelihood of 0.80.
	//
	// So severity leads, and likelihood orders what is equally severe.
	base := finding.Ranked{Shipped: true, ScoreCenti: 500}
	likelier := finding.Ranked{Shipped: true, ScoreCenti: 500, LikelihoodPPM: 900_000}
	worse := finding.Ranked{Shipped: true, ScoreCenti: 900}

	if likelier.Rank() <= base.Rank() {
		t.Error("a likelier issue did not outrank an identical one")
	}
	if worse.Rank() <= base.Rank() {
		t.Error("a more severe issue did not outrank an identical one")
	}
	// Severity is the stronger signal. What it gives up is letting a very
	// likely medium jump a high — and the case that actually matters, being
	// known to be used, is a fact rather than a forecast and ranks above both.
	if worse.Rank() <= likelier.Rank() {
		t.Error("likelihood outranked severity, which is the wrong way round")
	}
}

func TestASignalOutOfRangeCannotInventUrgency(t *testing.T) {
	// A source reporting something impossible would otherwise carry into the
	// band above and rank as though it were being exploited, which is the one
	// thing this must never invent.
	absurd := finding.Ranked{LikelihoodPPM: 999_000_000, ScoreCenti: 999_000}
	exploited := finding.Ranked{Exploited: true}
	if absurd.Rank() >= exploited.Rank() {
		t.Error("an out-of-range signal ranked as though it were exploited")
	}
	negatives := finding.Ranked{LikelihoodPPM: -5, ScoreCenti: -5}
	if negative := negatives.Rank(); negative != 0 {
		t.Errorf("negative signals produced %d, want 0", negative)
	}
}

func TestAWordStandsInWhereThereIsNoNumber(t *testing.T) {
	// Most findings carry a number; this is what stops the rest sorting below
	// everything rated at all.
	if finding.SeverityScore("critical") <= finding.SeverityScore("high") {
		t.Error("critical did not outrank high")
	}
	if finding.SeverityScore("negligible") <= 0 {
		t.Error("the lowest rated band scored nothing")
	}
	if finding.SeverityScore("") != 0 || finding.SeverityScore("unknown") != 0 {
		t.Error("an unrated issue was given a score")
	}
}
