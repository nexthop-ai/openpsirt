package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestSeverityLeadsAndLikelihoodBreaksTies(t *testing.T) {
	// The case that forced this ordering. A 2004 negligible with no score and
	// a high published likelihood outranked every critical, because likelihood
	// owned a band above severity and any difference in it won outright.
	negligible := finding.Ranked{Shipped: true, LikelihoodPPM: 802_900, ScoreCenti: 0}
	critical := finding.Ranked{Shipped: true, LikelihoodPPM: 73_100, ScoreCenti: 910}
	if negligible.Rank() >= critical.Rank() {
		t.Errorf("a negligible with no score outranks a critical: %d vs %d",
			negligible.Rank(), critical.Rank())
	}

	// Severity orders the list, whatever the likelihoods are. Measured on a
	// real image, 95% of issues sit inside one order of magnitude of
	// likelihood — so letting it reorder severities moves things on noise.
	worse := finding.Ranked{Shipped: true, ScoreCenti: 950, LikelihoodPPM: 1_000}
	milder := finding.Ranked{Shipped: true, ScoreCenti: 550, LikelihoodPPM: 900_000}
	if worse.Rank() <= milder.Rank() {
		t.Errorf("a critical does not outrank a medium: %d vs %d", worse.Rank(), milder.Rank())
	}

	// Among things equally severe, the likelier one rises. That is the whole
	// of what likelihood decides.
	likely := finding.Ranked{Shipped: true, ScoreCenti: 800, LikelihoodPPM: 400_000}
	unlikely := finding.Ranked{Shipped: true, ScoreCenti: 800, LikelihoodPPM: 2_000}
	if likely.Rank() <= unlikely.Rank() {
		t.Error("two equally severe issues do not order by likelihood")
	}

	// Severity still orders where nothing is published about likelihood, which
	// on a real image is only a handful — but they must not all tie.
	for _, pair := range [][2]int{{950, 800}, {800, 550}, {550, 300}, {300, 100}} {
		high := finding.Ranked{Shipped: true, ScoreCenti: pair[0]}
		low := finding.Ranked{Shipped: true, ScoreCenti: pair[1]}
		if high.Rank() <= low.Rank() {
			t.Errorf("with no likelihood, %d does not outrank %d", pair[0], pair[1])
		}
	}

	// Being exploited is a fact about the world rather than a forecast, and
	// outranks everything — including the worst thing that is merely predicted.
	exploited := finding.Ranked{Exploited: true, ScoreCenti: 100}
	worst := finding.Ranked{Shipped: true, LikelihoodPPM: 1_000_000, ScoreCenti: 1_000}
	if exploited.Rank() <= worst.Rank() {
		t.Error("something known to be exploited does not outrank everything else")
	}

	// And reaching customers still outranks severity, which is the band above
	// it: a critical in something only the build system runs matters less than
	// a medium people install.
	shipped := finding.Ranked{Shipped: true, ScoreCenti: 100}
	internal := finding.Ranked{ScoreCenti: 1_000}
	if shipped.Rank() <= internal.Rank() {
		t.Error("something that ships does not outrank something that does not")
	}
}
