// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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
			// The newest generation, wherever the report put it, because it
			// is the one a screen shows.
			"both, version 3 first",
			[]publishedRating{published("3.1", three, 8.2), published("4.0", four, 7.1)},
			"4.0", four, 7.1,
		},
		{
			"a rating stating no vector, ahead of one that does",
			[]publishedRating{published("4.0", "", 9.1), published("4.0", four, 7.1)},
			"4.0", four, 7.1,
		},
	} {
		t.Run(c.what, func(t *testing.T) {
			got, _ := rating(c.carries)
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

func TestARatingStatingNoGenerationTakesTheOneItsVectorStates(t *testing.T) {
	// A report is not required to say which generation a rating is on, and
	// some do not: the rating is taken on a score and a vector alone. The
	// vector states its own generation, so the number is placeable either way
	// rather than sitting bare beside one from the other scheme.
	for _, c := range []struct{ vector, want string }{
		{four, "4.0"},
		{three, "3.1"},
	} {
		t.Run(c.want, func(t *testing.T) {
			got, _ := rating([]publishedRating{published("", c.vector, 7.1)})
			if got.version != "" {
				t.Fatalf("the reader invented a generation of %q", got.version)
			}
			scored, err := finding.Score(got.vector)
			if err != nil {
				t.Fatalf("scoring what was recorded: %v", err)
			}
			if scored.Scheme() != c.want {
				t.Errorf("the vector reads as %q, want %q", scored.Scheme(), c.want)
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
			got, _ := rating([]publishedRating{published("", vector, 1)})
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

func TestBothGenerationsAreKeptWhereAReportStatesBoth(t *testing.T) {
	// The screen shows the newest and a published advisory states the one its
	// format has a field for, so neither can be the one thrown away.
	_, kept := rating([]publishedRating{
		published("3.1", three, 8.2),
		// A second version 3 rating from somebody else: the first stated in
		// a generation is the one kept.
		published("3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
		published("4.0", four, 7.1),
		// Version 2 names no scheme in its vector, and says so in its version.
		published("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5),
	})
	if len(kept) != 3 {
		t.Fatalf("kept %d ratings, want one per generation: %+v", len(kept), kept)
	}
	for at, want := range []struct {
		generation, centi int
		vector            string
	}{
		{4, 710, four},
		{3, 820, three},
		{2, 750, "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
	} {
		got := kept[at]
		if got.Generation != want.generation || got.ScoreCenti != want.centi || got.Vector != want.vector {
			t.Errorf("rating %d is %+v, want generation %d at %d with its own vector",
				at, got, want.generation, want.centi)
		}
		if got.Source != "nvd@nist.gov" || got.Kind != "Primary" {
			t.Errorf("rating %d lost who published it: %+v", at, got)
		}
	}
	if _, none := rating(nil); none != nil {
		t.Errorf("a report stating no rating kept %+v", none)
	}
}
