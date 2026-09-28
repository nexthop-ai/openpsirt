// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import "testing"

// Every standing the list offers is one the row can say, the list can filter
// by and the register can filter by. The four are spelled in four places — the
// word a group draws, the word one place draws, the list's condition and the
// register's — and a standing any one of them does not know puts a row in one
// bucket while it reads as another, or in none.
func TestEveryStandingIsSaidAndFilteredByTheSameRules(t *testing.T) {
	drawn := map[ClaimStanding]bool{}
	for places := 1; places <= 2; places++ {
		for waiting := 0; waiting <= 1; waiting++ {
			for approved := 0; approved <= places; approved++ {
				for lapsed := 0; lapsed <= 1; lapsed++ {
					drawn[stateWord(places, waiting, approved, lapsed)] = true
				}
			}
		}
	}
	placed := map[ClaimStanding]bool{}
	for _, decision := range []string{"", "proposed", "approved", "withdrawn", "lapsed"} {
		placed[placeStanding(decision)] = true
	}

	checked := 0
	for _, standing := range ClaimStandings() {
		checked++
		if stateHaving(standing) == "" {
			t.Errorf("the list cannot filter by %q", standing)
		}
		if _, known := registerState(standing); !known {
			t.Errorf("the register cannot filter by %q", standing)
		}
		if !drawn[standing] {
			t.Errorf("no group draws %q", standing)
		}
		if !placed[standing] {
			t.Errorf("no place draws %q", standing)
		}
	}
	if checked == 0 {
		t.Fatal("no standing was listed, so this checked nothing")
	}

	// And a word outside the list is refused by both filters rather than
	// read as some condition.
	if stateHaving("settled") != "" {
		t.Error("the list filters by a standing it does not list")
	}
	if _, known := registerState("settled"); known {
		t.Error("the register filters by a standing it does not list")
	}
}
