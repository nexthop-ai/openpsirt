// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Every standing an occurrence can have is said in words of its own, and a group
// that is none of the standings is said to be part decided.
func TestEveryStandingIsSaidInWordsOfItsOwn(t *testing.T) {
	cases := map[finding.DecisionStanding]string{
		finding.StandingAgreed:    "agreed",
		finding.StandingWaiting:   "waiting for a second person",
		finding.StandingLapsed:    "the decision here no longer stands",
		finding.StandingUndecided: "nobody has said",
		"":                        "part decided",
	}
	for _, state := range finding.DecisionStandings() {
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

// The count of occurrences a decision stands at is said for none, for one and
// for several, each in its own words.
func TestTheStandingCountIsSaidForNoneOneAndSeveral(t *testing.T) {
	for n, want := range map[int]string{
		0: "No decision stands at any occurrence",
		1: "A decision stands at 1 occurrence",
		2: "Decisions stand at 2 occurrences",
	} {
		if got := decisionsStand(n); got != want {
			t.Errorf("%d standing is said as %q, want %q", n, got, want)
		}
	}
}
