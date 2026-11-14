// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch

import (
	"testing"
	"time"
)

// A visit its process did not survive says nothing about the host, so it holds
// back no other repository there; a visit that failed does.
func TestAVisitThatDidNotFinishHoldsBackNoHost(t *testing.T) {
	now := time.Now().UTC()
	visited := now.Add(-time.Hour)
	for _, tc := range []struct {
		name   string
		failed string
		down   bool
	}{
		{"unfinished", unfinished, false},
		{"failed", "the host did not answer", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failed := tc.failed
			repositories := []repositoryRow{
				{URL: "https://git.example.test/one.git", FetchedAt: &visited, Failed: &failed},
				{URL: "https://git.example.test/two.git"},
			}
			down := hostsDown(repositories, now)
			if down["git.example.test"] != tc.down {
				t.Errorf("a visit that ended %q holds back the host: %v, want %v", tc.failed,
					down["git.example.test"], tc.down)
			}
		})
	}
}
