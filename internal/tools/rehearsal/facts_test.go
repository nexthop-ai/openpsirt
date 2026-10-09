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
	if faults := Compare(before, after); len(faults) != 0 {
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
	faults := Compare(before, after)
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
