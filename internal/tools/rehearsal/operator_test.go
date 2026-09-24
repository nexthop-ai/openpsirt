// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// A token narrowed to an undisclosed role gains the disclosed one beside it,
// in the order a token writes its roles; one that names none is unchanged.
func TestATokensHoldsGainTheDisclosedRoleBesideAnUndisclosedOne(t *testing.T) {
	for _, c := range []struct{ holds, want string }{
		{"private-triage", "public-triage,private-triage"},
		{"approver,private-read", "approver,public-read,private-read"},
		{"public-read,public-triage", "public-read,public-triage"},
	} {
		if got := impliedHolds(c.holds); got != c.want {
			t.Errorf("%q became %q, want %q", c.holds, got, c.want)
		}
	}
}
