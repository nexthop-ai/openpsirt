// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Every outcome either has the status a document states it under, or is
// refused: an outcome nobody listed is never published under a default.
func TestEveryOutcomeIsStatedAsListedOrRefused(t *testing.T) {
	want := map[triage.Outcome]string{
		triage.NotApplicable: "not_affected",
		triage.Mismatched:    "not_affected",
		triage.AlreadyFixed:  "fixed",
		triage.WontFix:       "affected",
	}
	examined := 0
	for _, outcome := range triage.Outcomes() {
		examined++
		got, err := claimed(Issue{Name: "CVE-1"}, "pkg:a", "pkg:b", string(outcome), finding.Stated{})
		if status, listed := want[outcome]; listed {
			if err != nil || got.Status != status {
				t.Errorf("%s was stated as %q (%v), want %q", outcome, got.Status, err, status)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s was published as %q rather than refused", outcome, got.Status)
		}
	}
	if examined == 0 {
		t.Fatal("no outcome was examined, so this checked nothing")
	}
}

// Every outcome a covering read can hand the document has a status, so the
// refusal above is never reached by a claim the read selected.
func TestEveryOutcomeACoveringReadSelectsHasAStatus(t *testing.T) {
	stated := finding.StatedOutcomes()
	if len(stated) == 0 {
		t.Fatal("no outcome covers a place, so this checked nothing")
	}
	for _, outcome := range stated {
		if statusOf(outcome) == "" {
			t.Errorf("%s covers a place and has no VEX status", outcome)
		}
	}
}
