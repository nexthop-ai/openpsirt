// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestAnUpgradeThatKeepsEveryRowItShouldIsNotReported(t *testing.T) {
	before := Counts{"finding": 10, "disclosure_extension": 2, "advisory_issuance": 3}
	after := Counts{"finding": 10, "disclosure_movement": 2, "advisory_issuance": 3,
		"advisory": 2, "advisory_edition": 2, "advisory_issue": 2, "told_outside": 0}
	if faults := Compare(before, after, rules("v0.1.0")); len(faults) != 0 {
		t.Errorf("a faithful upgrade was reported: %v", faults)
	}
}

func TestEveryRowAnUpgradeLosesOrInventsIsReported(t *testing.T) {
	before := Counts{"finding": 10, "disclosure_extension": 2, "advisory_issuance": 3, "scan": 4}
	after := Counts{
		"finding":              9, // a row lost
		"disclosure_extension": 2, // a table the upgrade removes, left behind
		"disclosure_movement":  1, // one extension not carried
		"advisory_issuance":    3,
		"advisory":             4, // more advisories than issuances
		"advisory_edition":     0, // none, though something was issued
		// advisory_issue is not made at all
		"told_outside": 1, // a new table something filled
		// scan is gone with no rule saying where its rows went
	}
	faults := Compare(before, after, rules("v0.1.0"))
	for _, table := range []string{"finding", "disclosure_extension", "disclosure_movement",
		"advisory ", "advisory_edition", "advisory_issue", "told_outside", "scan"} {
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
	if len(faults) != 8 {
		t.Errorf("want eight faults, got %d: %v", len(faults), faults)
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

func TestASettingTheUpgradeDropsIsExpectedAndNoMore(t *testing.T) {
	before := Counts{"application_setting": 3}
	if faults := Compare(before, Counts{"application_setting": 2}, dropped(1)); len(faults) != 0 {
		t.Errorf("dropping the one setting the upgrade removes was reported: %v", faults)
	}
	if faults := Compare(before, Counts{"application_setting": 1}, dropped(1)); len(faults) != 1 {
		t.Errorf("losing a second setting was not reported: %v", faults)
	}
	if faults := Compare(before, Counts{"application_setting": 2}, dropped(0)); len(faults) != 1 {
		t.Errorf("a setting lost with none expected was not reported: %v", faults)
	}
}
