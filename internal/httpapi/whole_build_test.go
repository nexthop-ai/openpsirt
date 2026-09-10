package httpapi_test

import (
	"testing"
)

// A request that names one whole build has already said which release it means,
// so the two filters that choose between releases have nothing left to choose.
//
// Applied anyway, their defaults — branches, in support — answered "0 of 0"
// about a tag holding twenty-five findings: correct filters answering a
// question the caller did not ask. A release past its end of life read the same
// way, which is worse, because that is the pile nothing else counts.
func TestNamingOneWholeBuildIsNotNarrowedByWhatKindOfReleaseItIs(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		_ = place

		var onBranch struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings?stream=master&variant=broadcom", &onBranch)
		if onBranch.Total == 0 {
			t.Fatal("the fixture's branch build holds nothing, so this proves nothing")
		}

		// The same build, asked for with the filter that would exclude it if
		// it were applied. Naming both is what makes it one build.
		var asked struct {
			Total int `json:"total"`
		}
		read(t, r, "triager",
			"/v1/products/mine/findings?stream=master&variant=broadcom&on=tag", &asked)
		if asked.Total != onBranch.Total {
			t.Errorf("naming one build and asking for tags answered %d, want %d — the "+
				"selection already named the release", asked.Total, onBranch.Total)
		}
	})
}

// The list of what a release was built as carried no count at all, so every
// screen drawing the column drew zeroes — including for a variant holding
// twenty-five, which reads as a clean build rather than as a number nobody
// filled in.
func TestWhatAReleaseWasBuiltAsSaysHowMuchIsOpenInEach(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		var built struct {
			Items []struct {
				Name string `json:"name"`
				Open int    `json:"open"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants", &built)
		if len(built.Items) == 0 {
			t.Fatal("the fixture's branch was built as nothing, so this proves nothing")
		}
		total := 0
		for _, one := range built.Items {
			total += one.Open
		}
		if total == 0 {
			t.Error("every variant of a release with findings in it reports nothing open")
		}
	})
}
