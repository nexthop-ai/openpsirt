// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"testing"
	"time"

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
// refusal above is never reached by a decision the read selected.
func TestEveryOutcomeACoveringReadSelectsHasAStatus(t *testing.T) {
	stated := finding.StatedOutcomes()
	if len(stated) == 0 {
		t.Fatal("no outcome covers an occurrence, so this checked nothing")
	}
	for _, outcome := range stated {
		if statusOf(outcome) == "" {
			t.Errorf("%s covers an occurrence and has no VEX status", outcome)
		}
	}
}

// A supplier's statement is stated in its own words or not at all: a group
// whose closing finding the second read missed is left out, never given the
// words of whichever statement was read first.
func TestASupplierStatementIsNeverStatedInAnothersWords(t *testing.T) {
	rows := []closedGroup{
		{VulnerabilityID: 1, Identifier: "CVE-2026-1", Component: "libnl", First: 5},
		{VulnerabilityID: 2, Identifier: "CVE-2026-2", Component: "zlib", First: 7},
	}
	read := []supplierWords{{ID: 7, Publisher: "Zlib Project", Product: "zlib"}}
	stated := attributedTo(rows, read)
	if len(stated) != 1 || stated[0].Component != "zlib" || stated[0].Publisher != "Zlib Project" {
		t.Errorf("stated %+v, want zlib alone in the Zlib Project's words", stated)
	}
}

// A fix is stated as of when it was seen or not at all: a group whose closing
// finding the second read missed is never stated fixed at the zero moment.
func TestAFixIsNeverStatedWithoutTheMomentItWasSeen(t *testing.T) {
	seen := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	rows := []closedGroup{
		{VulnerabilityID: 1, Identifier: "CVE-2026-1", Component: "libnl", First: 5},
		{VulnerabilityID: 2, Identifier: "CVE-2026-2", Component: "zlib", First: 7},
	}
	fixed := datedFixes(rows, map[int64]time.Time{7: seen})
	if len(fixed) != 1 || fixed[0].Component != "zlib" || !fixed[0].PatchedAt.Equal(seen) {
		t.Errorf("stated %+v fixed, want zlib alone, as of %v", fixed, seen)
	}
}
