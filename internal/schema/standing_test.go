// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package schema

import "testing"

// A serving instance serves a schema at its own version that nothing is
// changing, pauses for one being changed, stops for one behind it that nothing
// is changing, and never serves one a later release applied, even while that
// release is still changing it.
func TestAStandingFollowsTheLockAndTheVersion(t *testing.T) {
	for _, c := range []struct {
		changing         bool
		applied, carried int64
		want             Standing
	}{
		{false, 47, 47, Serves},
		{true, 47, 47, Changes},
		{false, 46, 47, Behind},
		{true, 46, 47, Changes},
		{false, 48, 47, Superseded},
		{true, 48, 47, Superseded},
	} {
		if got := stands(c.changing, c.applied, c.carried); got != c.want {
			t.Errorf("changing %v at %d, carrying %d: %v, want %v", c.changing, c.applied, c.carried, got, c.want)
		}
	}
}
