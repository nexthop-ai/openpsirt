// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"strings"
	"testing"
)

// The rule under another alias is the same rule: every reference to the
// decision and the outcome is renamed, and nothing else changes.
func TestTheVersionMatchUnderAnotherAliasIsTheSameRule(t *testing.T) {
	if got := keyMatchesOn("de", "cl.outcome"); got != KeyMatches {
		t.Fatalf("under its own aliases the rule reads %q, want %q", got, KeyMatches)
	}
	renamed := keyMatchesOn("d2", "(SELECT x)")
	for _, gone := range []string{"de.", "cl.outcome"} {
		if strings.Contains(renamed, gone) {
			t.Errorf("renamed, the rule still names %q: %s", gone, renamed)
		}
	}
	for _, want := range []string{"d2.component_upstream_version", "d2.consumer_upstream_version",
		"(SELECT x) = '" + Mismatched + "'", ComponentUpstreamExpr, ConsumerUpstreamExpr} {
		if !strings.Contains(renamed, want) {
			t.Errorf("renamed, the rule does not name %q: %s", want, renamed)
		}
	}
}
