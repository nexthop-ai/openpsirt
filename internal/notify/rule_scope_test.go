// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
)

// A suppression rule is named in the same words whichever notice names it,
// and one proposed with a path prefix alone names every code finding there.
func TestASuppressionRuleNamedByItsPrefixAloneSaysEveryCodeFinding(t *testing.T) {
	for _, each := range []struct {
		rule analysis.SuppressionRule
		want string
	}{
		{analysis.SuppressionRule{Prefix: "vendor/"}, "every code finding under vendor/"},
		{analysis.SuppressionRule{Rule: "go.lang.sqli", Prefix: "src/"}, "go.lang.sqli under src/"},
		{analysis.SuppressionRule{Rule: "go.lang.sqli"}, "go.lang.sqli"},
	} {
		if got := ruleScope(each.rule); got != each.want {
			t.Errorf("%+v is named %q, want %q", each.rule, got, each.want)
		}
	}
}
