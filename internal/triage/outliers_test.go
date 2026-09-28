// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"fmt"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// bulkOver is a bulk claim's issues as outliersOf reads them: one row each,
// rated by the word given, attacked here where marked.
func bulkOver(words []string, attackedHere []bool) (map[int64][]int64,
	map[int64]finding.Vulnerability, map[int64]bool) {

	decisionsOf := map[int64][]int64{}
	byIssue := map[int64]finding.Vulnerability{}
	attacked := map[int64]bool{}
	for i, word := range words {
		id := int64(i + 1)
		decisionsOf[id] = []int64{id * 10}
		byIssue[id] = finding.Vulnerability{
			ID: id, Identifier: fmt.Sprintf("CVE-2026-%04d", id), Severity: word,
		}
		attacked[id] = attackedHere[i]
	}
	return decisionsOf, byIssue, attacked
}

func TestNoAttackedIssueIsLeftOffABulkClaimsCard(t *testing.T) {
	// Agreeing is refused while an attacked issue is in the claim, so it is
	// the row an approver has to set aside. The cap gives way to it, and
	// everything else past the cap is dropped.
	words := make([]string, outlierRows+5)
	attackedHere := make([]bool, outlierRows+5)
	for i := range words {
		if i < outlierRows+2 {
			words[i], attackedHere[i] = "low", true
		} else {
			words[i] = "critical"
		}
	}
	decisionsOf, byIssue, attacked := bulkOver(words, attackedHere)
	out := outliersOf(Claim{}, 1, decisionsOf, byIssue, nil, nil, attacked)

	if len(out.Rows) != outlierRows+2 {
		t.Fatalf("the card carries %d rows, want every one of the %d attacked issues",
			len(out.Rows), outlierRows+2)
	}
	for _, row := range out.Rows {
		if !row.ExploitedHere {
			t.Errorf("%s is on the card past the cap and was not attacked here", row.Vulnerability)
		}
	}
}

func TestABulkClaimsCardIsCappedAttackedFirstThenWorstThenByName(t *testing.T) {
	// Under the cap's pressure what stays is what matters most, in an order
	// that is the same on every engine.
	words := make([]string, outlierRows+10)
	attackedHere := make([]bool, outlierRows+10)
	for i := range words {
		switch {
		case i < 2:
			words[i], attackedHere[i] = "low", true
		case i%2 == 0:
			words[i] = "high"
		default:
			words[i] = "critical"
		}
	}
	decisionsOf, byIssue, attacked := bulkOver(words, attackedHere)
	out := outliersOf(Claim{}, 1, decisionsOf, byIssue, nil, nil, attacked)

	if len(out.Rows) != outlierRows {
		t.Fatalf("the card carries %d rows, want the cap of %d", len(out.Rows), outlierRows)
	}
	if !out.Rows[0].ExploitedHere || !out.Rows[1].ExploitedHere {
		t.Errorf("the attacked issues do not lead: %s, %s",
			out.Rows[0].Vulnerability, out.Rows[1].Vulnerability)
	}
	for i := 3; i < len(out.Rows); i++ {
		a, b := out.Rows[i-1], out.Rows[i]
		if finding.Ranks(a.Severity) < finding.Ranks(b.Severity) {
			t.Errorf("%s (%s) is before %s (%s)", a.Vulnerability, a.Severity, b.Vulnerability, b.Severity)
		}
		if a.Severity == b.Severity && a.Vulnerability > b.Vulnerability {
			t.Errorf("%s is before %s at the same rating", a.Vulnerability, b.Vulnerability)
		}
	}
	if last := out.Rows[len(out.Rows)-1]; last.Severity != "high" {
		t.Errorf("the card ends on %s (%s); every critical issue fits, so it ends on a high one",
			last.Vulnerability, last.Severity)
	}
}
