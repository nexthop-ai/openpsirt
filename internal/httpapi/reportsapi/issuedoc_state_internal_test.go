// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Every standing a place can have is said in words of its own, and a group
// that is none of the standings is said to be part decided.
func TestEveryStandingIsSaidInWordsOfItsOwn(t *testing.T) {
	cases := map[finding.ClaimStanding]string{
		finding.StandingAgreed:    "agreed",
		finding.StandingWaiting:   "waiting for a second person",
		finding.StandingLapsed:    "the judgment here no longer stands",
		finding.StandingUndecided: "nobody has said",
		"":                        "part decided",
	}
	for _, state := range finding.ClaimStandings() {
		if _, ok := cases[state]; !ok {
			t.Errorf("the standing %q has no case here", state)
		}
	}
	for state, want := range cases {
		if got := stateSaid(state); got != want {
			t.Errorf("%q is said as %q, want %q", state, got, want)
		}
	}
}
