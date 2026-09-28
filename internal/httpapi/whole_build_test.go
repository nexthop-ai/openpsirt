// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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

// Counting what is open is the expensive half of a catalog read, so it is
// asked for rather than always done. Both directions are pinned on every path
// that takes the parameter.
//
// Unasked, it must never come back as a zero: the screens that draw this
// column render a missing number as "0", and a variant holding findings reads
// as a clean build. Asked, it must be the number.
func TestACatalogListCountsWhatWasAskedForAndNothingOtherwise(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		for _, path := range []string{
			"/v1/products",
			"/v1/products/mine/streams",
			"/v1/products/mine/variants",
			"/v1/products/mine/streams/master/variants",
		} {
			var list struct {
				Items []struct {
					Name string `json:"name"`
					Open *int   `json:"open"`
				} `json:"items"`
			}
			read(t, r, "triager", path, &list)
			if len(list.Items) == 0 {
				t.Fatalf("%s came back empty, so this proves nothing", path)
			}
			for _, one := range list.Items {
				if one.Open != nil {
					t.Errorf("%s: %q reports open=%d where nobody asked for a count",
						path, one.Name, *one.Open)
				}
			}

			// And the other direction on the same path. Pinned per path
			// rather than once: each of these counts through a scope of its
			// own, so a handler that stopped counting would leave the screen
			// drawing this column at zero with the suite still green.
			var counted struct {
				Items []struct {
					Name string `json:"name"`
					Open *int   `json:"open"`
				} `json:"items"`
			}
			read(t, r, "triager", path+"?counts=true", &counted)
			total := 0
			for _, one := range counted.Items {
				if one.Open == nil {
					t.Fatalf("%s: %q reports no count where one was asked for", path, one.Name)
				}
				total += *one.Open
			}
			if total == 0 {
				t.Errorf("%s: a fixture with findings in it counts nothing open", path)
			}
		}
	})
}
