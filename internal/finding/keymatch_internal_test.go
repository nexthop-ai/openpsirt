// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"strings"
	"testing"
)

// The rule under another alias is the same rule: every reference to the
// decision occurrence and the outcome is renamed, and nothing else changes.
func TestTheVersionMatchUnderAnotherAliasIsTheSameRule(t *testing.T) {
	if got := keyMatchesOn("de", `"cl"."outcome"`); got != KeyMatches {
		t.Fatalf("under its own aliases the rule reads %q, want %q", got, KeyMatches)
	}
	renamed := keyMatchesOn("d2", "(SELECT x)")
	for _, gone := range []string{`"de".`, `"cl"."outcome"`} {
		if strings.Contains(renamed, gone) {
			t.Errorf("renamed, the rule still names %q: %s", gone, renamed)
		}
	}
	for _, want := range []string{`"d2"."component_upstream_version"`, `"d2"."consumer_upstream_version"`,
		"(SELECT x) IN (" + anyVersionList + ")", ComponentUpstreamExpr, ConsumerUpstreamExpr} {
		if !strings.Contains(renamed, want) {
			t.Errorf("renamed, the rule does not name %q: %s", want, renamed)
		}
	}
}

// The version a component is at reads the same under every alias, and the two
// constants other constants are built from are that expression over theirs.
func TestTheUpstreamVersionIsOneExpressionUnderEveryAlias(t *testing.T) {
	if got := upstreamVersionOf("c"); got != ComponentUpstreamExpr {
		t.Errorf("over c the version reads %q, want %q", got, ComponentUpstreamExpr)
	}
	if got := upstreamVersionOf("uc"); got != ConsumerUpstreamExpr {
		t.Errorf("over uc the version reads %q, want %q", got, ConsumerUpstreamExpr)
	}
	if got, want := upstreamVersionOf("cp"), `COALESCE(NULLIF("cp"."upstream_version", ''), "cp"."version", '')`; got != want {
		t.Errorf("over cp the version reads %q, want %q", got, want)
	}
}

// The sets a VEX document reads compare the two sides of the version match
// themselves, so each side read as a column is the expression the rule
// compares.
func TestTheVersionsReadForTheMatchAreTheSidesOfTheRule(t *testing.T) {
	for _, side := range []struct{ got, want string }{
		{keyedComponent, `COALESCE("de"."component_upstream_version", '')`},
		{heldComponent, ComponentUpstreamExpr},
		{keyedConsumer, `COALESCE("de"."consumer_upstream_version", '')`},
	} {
		if side.got != side.want {
			t.Errorf("a side of the match reads %q, want %q", side.got, side.want)
		}
	}
	if VersionsMatch != keyedComponent+" = "+heldComponent+" AND "+keyedConsumer+" = "+ConsumerUpstreamExpr {
		t.Errorf("the match is no longer the two equalities read: %s", VersionsMatch)
	}
}
