// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// A findings file states the severity it was read at, and everything where
// the minimum severity hides nothing, under one label.
func TestAFindingsFileStatesTheSeverityItWasReadAt(t *testing.T) {
	for _, c := range []struct {
		floor finding.MinimumSeverity
		want  string
	}{
		{finding.MinimumSeverity{Word: "medium"}, "medium"},
		{finding.MinimumSeverity{Word: finding.NoMinimumSeverity}, "everything"},
		{finding.MinimumSeverity{}, "everything"},
	} {
		got := TriagedAtOrAbove(c.floor)
		if got.Label != "triaged at or above" || got.Value != c.want {
			t.Errorf("a minimum severity of %q is stated as %+v", c.floor.Word, got)
		}
	}
}
