// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestAnUpgradeThatKeepsEveryRowIsNotReported(t *testing.T) {
	before := Counts{"finding": 10, "advisory_issuance": 3}
	after := Counts{"finding": 10, "advisory_issuance": 3, "told_place": 0}
	if faults := Compare(before, after, Counts{}); len(faults) != 0 {
		t.Errorf("a faithful upgrade was reported: %v", faults)
	}
}

func TestEveryRowAnUpgradeLosesOrInventsIsReported(t *testing.T) {
	before := Counts{"finding": 10, "advisory_issuance": 3, "scan": 4}
	after := Counts{
		"finding":           9, // a row lost
		"advisory_issuance": 3,
		"told_place":        1, // a new table something filled
		// scan is gone with no rule saying where its rows went
	}
	faults := Compare(before, after, Counts{})
	for _, table := range []string{"finding", "told_place", "scan"} {
		found := false
		for _, fault := range faults {
			if strings.HasPrefix(fault, table) {
				found = true
			}
		}
		if !found {
			t.Errorf("nothing reported %s: %v", table, faults)
		}
	}
	if len(faults) != 3 {
		t.Errorf("want three faults, got %d: %v", len(faults), faults)
	}
}

func TestATotalThatMovesOrVanishesIsReported(t *testing.T) {
	before := Totals{"sonic/master/broadcom": 5, "sonic/master/mellanox": 6, "openpsirt/main/binary": 1}
	if faults := CompareTotals("open", before, Totals{
		"sonic/master/broadcom": 5, "sonic/master/mellanox": 6, "openpsirt/main/binary": 1,
	}); len(faults) != 0 {
		t.Errorf("equal totals were reported: %v", faults)
	}
	faults := CompareTotals("open", before, Totals{"sonic/master/broadcom": 4, "sonic/master/mellanox": 6, "x/y/z": 1})
	if len(faults) != 3 {
		t.Errorf("want a moved total, a missing build and a new one, got %v", faults)
	}
}

func TestARenamedTableKeepsItsRowsUnderItsNewName(t *testing.T) {
	renamed := map[string]string{"decision": "decision_occurrence", "claim": "decision"}
	held := Counts{"decision": 12, "claim": 5, "finding": 40}
	after := Counts{"decision_occurrence": 12, "decision": 5, "finding": 40}
	if faults := Compare(AsRenamed(renamesV0110-1, held, renamed), after, Counts{}); len(faults) != 0 {
		t.Errorf("a rename that kept every row was reported: %v", faults)
	}
	if faults := Compare(AsRenamed(renamesV0110-1, held, renamed), Counts{"decision_occurrence": 11, "decision": 5,
		"finding": 40}, Counts{}); len(faults) != 1 || !strings.HasPrefix(faults[0], "decision_occurrence") {
		t.Errorf("a row lost from a renamed table was not reported under its new name: %v", faults)
	}
}

func TestATableIsRenamedOnlyByAnUpgradeThatRenamesIt(t *testing.T) {
	held := Counts{"decision": 12}
	got := AsRenamed(renamesV0110, held, map[string]string{"decision": "decision_occurrence"})
	if got["decision"] != 12 || len(got) != 1 {
		t.Errorf("a release already past the renames had its tables renamed: %v", got)
	}
}

func TestTheMessagesTheUpgradeWritesFromAcknowledgementsAreNotReported(t *testing.T) {
	before := Counts{"flaw_report": 7}
	after := Counts{"flaw_report": 7, "report_message": 4}
	if faults := Compare(before, after, FilledV0110(renamesV0110-1, 4)); len(faults) != 0 {
		t.Errorf("a message written for each acknowledgement was reported: %v", faults)
	}
}

func TestAMessageNoAcknowledgementAccountsForIsReported(t *testing.T) {
	before := Counts{"flaw_report": 7}
	after := Counts{"flaw_report": 7, "report_message": 5}
	faults := Compare(before, after, FilledV0110(renamesV0110-1, 4))
	if len(faults) != 1 || !strings.HasPrefix(faults[0], "report_message") {
		t.Errorf("a message beyond the acknowledgements was not reported: %v", faults)
	}
}

func TestAReleasePastTheUpgradeKeepsItsMessages(t *testing.T) {
	before := Counts{"flaw_report": 7, "report_message": 9}
	after := Counts{"flaw_report": 7, "report_message": 13}
	faults := Compare(before, after, FilledV0110(renamesV0110, 4))
	if len(faults) != 1 || !strings.HasPrefix(faults[0], "report_message") {
		t.Errorf("messages a later release held were counted as filled again: %v", faults)
	}
}
