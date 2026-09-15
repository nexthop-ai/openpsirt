package finding_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestWhatIsBeingExploitedComesFirst(t *testing.T) {
	// The one that has to hold whatever else is true. Something being used
	// against people is the difference between a risk and an incident, and no
	// combination of the other three may outrank it.
	// Each row keeps its own numbers: the packing can be right at one
	// magnitude and wrong at another, so two rows asserting one rule are two
	// tests rather than one written twice.
	for _, exploited := range []finding.Ranked{
		{Exploited: true},
		{Exploited: true, ScoreCenti: 100},
	} {
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
}

func TestWhatReachesCustomersOutranksWhatDoesNot(t *testing.T) {
	// A critical in something only the build system runs matters less than a
	// medium in what people install.
	for _, pair := range []struct{ shipped, internal finding.Ranked }{
		{finding.Ranked{Shipped: true, ScoreCenti: 550},
			finding.Ranked{ScoreCenti: 1000, LikelihoodPPM: 1_000_000}},
		// At another magnitude, and with nothing published about likelihood.
		{finding.Ranked{Shipped: true, ScoreCenti: 100},
			finding.Ranked{ScoreCenti: 1_000}},
	} {
		if pair.shipped.Rank() <= pair.internal.Rank() {
			t.Errorf("%+v ranked at or below %+v", pair.shipped, pair.internal)
		}
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

	// The same three rules at another magnitude, which is where a packing
	// mistake shows up if it did not show up above.
	critical := finding.Ranked{Shipped: true, ScoreCenti: 950, LikelihoodPPM: 1_000}
	medium := finding.Ranked{Shipped: true, ScoreCenti: 550, LikelihoodPPM: 900_000}
	if critical.Rank() <= medium.Rank() {
		t.Errorf("a critical does not outrank a medium: %d vs %d", critical.Rank(), medium.Rank())
	}
	likely := finding.Ranked{Shipped: true, ScoreCenti: 800, LikelihoodPPM: 400_000}
	unlikely := finding.Ranked{Shipped: true, ScoreCenti: 800, LikelihoodPPM: 2_000}
	if likely.Rank() <= unlikely.Rank() {
		t.Error("two equally severe issues do not order by likelihood")
	}
}

func TestANegligibleWithNoScoreDoesNotOutrankACritical(t *testing.T) {
	// The case that forced this ordering. A 2004 negligible with no score and
	// a high published likelihood outranked every critical, because likelihood
	// owned a band above severity and any difference in it won outright.
	negligible := finding.Ranked{Shipped: true, LikelihoodPPM: 802_900, ScoreCenti: 0}
	critical := finding.Ranked{Shipped: true, LikelihoodPPM: 73_100, ScoreCenti: 910}
	if negligible.Rank() >= critical.Rank() {
		t.Errorf("a negligible with no score outranks a critical: %d vs %d",
			negligible.Rank(), critical.Rank())
	}
}

func TestSeverityStillOrdersWhereNothingIsKnownAboutLikelihood(t *testing.T) {
	// On a real image only a handful carry no published likelihood, and they
	// must not all tie: a band of them at one number is a page in whatever
	// order the rows came back.
	for _, pair := range [][2]int{{950, 800}, {800, 550}, {550, 300}, {300, 100}} {
		high := finding.Ranked{Shipped: true, ScoreCenti: pair[0]}
		low := finding.Ranked{Shipped: true, ScoreCenti: pair[1]}
		if high.Rank() <= low.Rank() {
			t.Errorf("with no likelihood, %d does not outrank %d", pair[0], pair[1])
		}
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
	// The two words a scanner reports and no band holds are lows, which is
	// what the fold every query goes through already decided. Scored on their
	// own they sat above unrated and below every low, and a stored score
	// turned back into a word came out "low" anyway — a word nobody published
	// about the issue.
	for _, word := range []string{"negligible", "none"} {
		if finding.SeverityScore(word) != finding.SeverityScore("low") {
			t.Errorf("%q scores %d where the fold reads it as a low",
				word, finding.SeverityScore(word))
		}
		if finding.SeverityWord(finding.SeverityScore(word)) != finding.Band(word) {
			t.Errorf("%q scores to %q and folds to %q, which are two answers about one word",
				word, finding.SeverityWord(finding.SeverityScore(word)), finding.Band(word))
		}
	}
	if finding.SeverityScore("") != 0 || finding.SeverityScore("unknown") != 0 {
		t.Error("an unrated issue was given a score")
	}
}

func TestTheSeverityOrderingAndItsInverseAgree(t *testing.T) {
	// The order was written out by hand four times — the list, two SQL CASE
	// expressions and the mapping back to words — and Bands' own doc records
	// what that already cost once: a word added to one copy and missing from
	// another sorts one way and filters another. All four read the one list
	// now, and this is what holds that.
	bands := finding.Bands()
	if len(bands) == 0 {
		t.Fatal("no severity bands, so this checked nothing")
	}
	for _, word := range bands {
		rank := finding.Ranks(word)
		if rank == 0 {
			t.Errorf("%q is a band and ranks as unrecognized", word)
		}
		if back := finding.WordAt(rank); back != word {
			t.Errorf("%q ranks %d and %d reads back as %q", word, rank, rank, back)
		}
	}
	if finding.WordAt(0) != "" || finding.WordAt(len(bands)+1) != "" {
		t.Error("a rank no band holds reads back as a word")
	}

	// And the SQL says the same thing: one arm per band, at the same numbers.
	said := finding.RankCase("x", 0)
	for _, word := range bands {
		arm := fmt.Sprintf("WHEN '%s' THEN %d", word, finding.Ranks(word))
		if !strings.Contains(said, arm) {
			t.Errorf("the ordering in SQL has no %q", arm)
		}
	}
	if !strings.Contains(said, "ELSE 0 END") {
		t.Error("the ordering in SQL does not put what it does not recognize below every band")
	}
}
