// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"strings"
	"testing"
	"time"
)

// A version a decision states is bounded like the versions it is keyed on,
// counted in characters as sent, as the published bound counts it.
func TestAVersionADecisionStatesIsBoundedLikeTheVersionsItIsKeyedOn(t *testing.T) {
	now := time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)
	by := now.AddDate(0, 1, 0)
	for _, c := range []struct {
		name  string
		state func(p *Proposal, v string)
	}{
		{"the version the fix arrived in", func(p *Proposal, v string) {
			p.Outcome, p.FixedVersion = AlreadyFixed, v
		}},
		{"the version the upgrade moves to", func(p *Proposal, v string) {
			p.Outcome, p.UpgradeTo, p.CommittedTo = UpgradeNeeded, v, &by
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			propose := func(v string) error {
				p := Proposal{Reasoning: "Looked at it.", By: 1}
				c.state(&p, v)
				return p.valid(now)
			}
			if err := propose(strings.Repeat("é", versionLimit)); err != nil {
				t.Errorf("a version at the bound was refused: %v", err)
			}
			err := propose(strings.Repeat("9", versionLimit-1) + "  ")
			if err == nil {
				t.Fatal("a version past the bound was accepted")
			}
			if !strings.Contains(err.Error(), c.name) {
				t.Errorf("the refusal reads %q, which does not name %s", err, c.name)
			}
		})
	}
}
