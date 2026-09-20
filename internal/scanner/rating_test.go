package scanner

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// A rating as a report states it, with the score in the place a report puts it.
func published(version, vector string, score float64) publishedRating {
	one := publishedRating{Version: version, Vector: vector, Source: "nvd@nist.gov", Type: "Primary"}
	one.Metrics.BaseScore = score
	return one
}

// Real ratings, as the National Vulnerability Database publishes them. A
// version 4 vector carries every metric the scheme has, with X where nothing
// was stated; a version 3 vector carries the base metrics alone.
const (
	four  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X"
	three = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N"
)

func TestARatingIsRecordedUnderTheGenerationItWasStatedIn(t *testing.T) {
	// One issue is commonly rated under both generations, and the two numbers
	// are not comparable. Recording the number without the generation leaves
	// a reader to guess it from the vector, or to compare it with one from the
	// other scheme.
	for _, c := range []struct {
		what    string
		carries []publishedRating
		version string
		vector  string
		score   float64
	}{
		{"version 4 alone", []publishedRating{published("4.0", four, 7.1)}, "4.0", four, 7.1},
		{"version 3 alone", []publishedRating{published("3.1", three, 8.2)}, "3.1", three, 8.2},
		{
			"both, version 4 first",
			[]publishedRating{published("4.0", four, 7.1), published("3.1", three, 8.2)},
			"4.0", four, 7.1,
		},
		{
			"both, version 3 first",
			[]publishedRating{published("3.1", three, 8.2), published("4.0", four, 7.1)},
			"3.1", three, 8.2,
		},
		{
			"a rating stating no vector, ahead of one that does",
			[]publishedRating{published("4.0", "", 9.1), published("4.0", four, 7.1)},
			"4.0", four, 7.1,
		},
	} {
		t.Run(c.what, func(t *testing.T) {
			got := rating(c.carries)
			if got.version != c.version {
				t.Errorf("recorded the generation as %q, want %q", got.version, c.version)
			}
			if got.vector != c.vector {
				t.Errorf("recorded the vector as %q", got.vector)
			}
			if got.score != c.score {
				t.Errorf("recorded the score as %v, want the published %v", got.score, c.score)
			}
		})
	}
}

func TestAVectorARatingCarriesIsOneThisCanScore(t *testing.T) {
	// The vector a report states is stored whole and read back by everything
	// that shows the assumptions behind a number. A generation this cannot
	// score would leave that number unexplainable here.
	for _, vector := range []string{four, three} {
		t.Run(vector, func(t *testing.T) {
			got := rating([]publishedRating{published("", vector, 1)})
			scored, err := finding.Score(got.vector)
			if err != nil {
				t.Fatalf("the vector as recorded does not score here: %v", err)
			}
			if scored.Severity == "" {
				t.Error("the vector as recorded scores into no band")
			}
		})
	}
}
