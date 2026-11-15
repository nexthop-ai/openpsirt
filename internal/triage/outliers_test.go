// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"fmt"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// bulkOver is a bulk decision's issues as outliersOf reads them: one row each,
// rated by the word given, attacked here where marked.
func bulkOver(words []string, attackedHere []bool) (map[int64][]int64,
	map[int64]finding.Vulnerability, map[int64]bool) {

	occurrencesOf := map[int64][]int64{}
	byIssue := map[int64]finding.Vulnerability{}
	attacked := map[int64]bool{}
	for i, word := range words {
		id := int64(i + 1)
		occurrencesOf[id] = []int64{id * 10}
		byIssue[id] = finding.Vulnerability{
			ID: id, Identifier: fmt.Sprintf("CVE-2026-%04d", id), Severity: word,
		}
		attacked[id] = attackedHere[i]
	}
	return occurrencesOf, byIssue, attacked
}

func TestNoAttackedIssueIsLeftOffABulkDecisionsCard(t *testing.T) {
	// Agreeing is refused while an attacked issue is in the decision, so it is
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
	occurrencesOf, byIssue, attacked := bulkOver(words, attackedHere)
	out := outliersOf(Decision{}, 1, occurrencesOf, byIssue, nil, nil, attacked)

	if len(out.Rows) != outlierRows+2 {
		t.Fatalf("the card carries %d rows, want every one of the %d attacked issues",
			len(out.Rows), outlierRows+2)
	}
	for _, row := range out.Rows {
		if !row.Incident {
			t.Errorf("%s is on the card past the cap and was not attacked here", row.Vulnerability)
		}
	}
}

func TestABulkDecisionsCardIsCappedAttackedFirstThenWorstThenByName(t *testing.T) {
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
	occurrencesOf, byIssue, attacked := bulkOver(words, attackedHere)
	out := outliersOf(Decision{}, 1, occurrencesOf, byIssue, nil, nil, attacked)

	if len(out.Rows) != outlierRows {
		t.Fatalf("the card carries %d rows, want the cap of %d", len(out.Rows), outlierRows)
	}
	if !out.Rows[0].Incident || !out.Rows[1].Incident {
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

func TestABulkDecisionsCardRanksAnUnratedIssueByItsScore(t *testing.T) {
	// The card's severity order is the one every severity sort follows: an
	// unrated issue sorts in its score's band, and below a low with no score.
	occurrencesOf, byIssue, attacked := bulkOver(
		[]string{"unknown", "high", "unknown", "low"}, []bool{true, true, true, true})
	scored := byIssue[1]
	nine := 980
	scored.ScoreCenti = &nine
	byIssue[1] = scored
	seven := 700
	high := byIssue[2]
	high.ScoreCenti = &seven
	byIssue[2] = high

	out := outliersOf(Decision{}, 1, occurrencesOf, byIssue, nil, nil, attacked)
	var got []string
	for _, row := range out.Rows {
		got = append(got, row.Vulnerability)
	}
	want := []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0004", "CVE-2026-0003"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the card reads %v, want the unrated 9.8 first and the unscored unrated last: %v", got, want)
	}
}
