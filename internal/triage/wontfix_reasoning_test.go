// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"strings"
	"testing"
	"time"
)

// A decision that it will not be fixed and names nothing to do instead is
// published as no fix planned, so the reasoning a second person agrees to is
// the one record of why. One with no reasoning is refused.
func TestAWontFixNamingNothingToDoIsRefusedWithoutReasoning(t *testing.T) {
	now := time.Date(2026, time.November, 12, 12, 0, 0, 0, time.UTC)
	for _, reasoning := range []string{"", "  \n\t"} {
		refused := Proposal{Outcome: WontFix, Reasoning: reasoning, By: 1}.valid(now)
		if refused == nil || !strings.Contains(refused.Error(), "needs reasoning") {
			t.Errorf("a won't-fix with no mitigation and reasoning %q was answered %v, want "+
				"it refused for its reasoning", reasoning, refused)
		}
	}
	if err := (Proposal{Outcome: WontFix, Reasoning: "The protocol is fixed.", By: 1}).valid(now); err != nil {
		t.Errorf("a won't-fix with reasoning and no mitigation was refused: %v", err)
	}
}
