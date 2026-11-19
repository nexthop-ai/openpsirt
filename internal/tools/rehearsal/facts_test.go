// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestAnUpgradeThatKeepsEveryRowIsNotReported(t *testing.T) {
	before := Counts{"finding": 10, "advisory_issuance": 3}
	after := Counts{"finding": 10, "advisory_issuance": 3, "told_place": 0}
	if faults := Compare(before, after, nil); len(faults) != 0 {
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
	faults := Compare(before, after, nil)
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

func TestTheRowsAnUpgradeFillsATableWithAreNotReported(t *testing.T) {
	before := Counts{"component": 7}
	after := Counts{"component": 7, "component_name": 9}
	if faults := Compare(before, after, Counts{"component_name": 9}); len(faults) != 0 {
		t.Errorf("the rows a fill wrote were reported: %v", faults)
	}
}

func TestARowNoFillAccountsForIsReported(t *testing.T) {
	before := Counts{"component": 7}
	after := Counts{"component": 7, "component_name": 10}
	faults := Compare(before, after, Counts{"component_name": 9})
	if len(faults) != 1 || !strings.HasPrefix(faults[0], "component_name") || !strings.Contains(faults[0], "fills it with 9") {
		t.Errorf("a row beyond the fill was not reported against it: %v", faults)
	}
}

func TestAFilledTableTheReleaseHeldKeepsItsRowsAndTheFill(t *testing.T) {
	before := Counts{"component_name": 3}
	if faults := Compare(before, Counts{"component_name": 5}, Counts{"component_name": 2}); len(faults) != 0 {
		t.Errorf("a held table's rows and its fill were reported: %v", faults)
	}
	if faults := Compare(before, Counts{"component_name": 4}, Counts{"component_name": 2}); len(faults) != 1 {
		t.Errorf("a held table short of its rows and its fill was not reported: %v", faults)
	}
}

func TestOnlyAMigrationTheReleaseDidNotApplyFills(t *testing.T) {
	fills := []Fill{{Migration: 48, Table: "component_name"}}
	if owed := Owed(47, fills); len(owed) != 1 {
		t.Errorf("a release before the fill owes %v, want the fill", owed)
	}
	if owed := Owed(48, fills); len(owed) != 0 {
		t.Errorf("a release that applied the fill owes %v, want nothing", owed)
	}
}

func TestASeedThatLeftATableEmptyIsRefused(t *testing.T) {
	held := Counts{"finding": 3, "decision": 2, "decision_occurrence": 2, "received_vex_statement": 1, "flaw_report": 1}
	if empty := Unseeded(held); len(empty) != 0 {
		t.Errorf("a full seed was refused: %v", empty)
	}
	delete(held, "received_vex_statement")
	if empty := Unseeded(held); !slices.Equal(empty, []string{"received_vex_statement"}) {
		t.Errorf("want received_vex_statement reported, got %v", empty)
	}
}

func TestARequiredTableThatCannotBeCountedStopsTheRun(t *testing.T) {
	ask := func(table string) (int64, error) {
		if table == "finding" {
			return 0, errors.New("lock wait timeout")
		}
		return 4, nil
	}
	_, err := Tally([]string{"scan", "finding"}, map[string]bool{"scan": true, "finding": true}, ask, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "finding") {
		t.Fatalf("a required table that could not be counted was not refused by name: %v", err)
	}
}

func TestAnOptionalTableThatCannotBeCountedIsLeftOut(t *testing.T) {
	ask := func(table string) (int64, error) {
		if table == "old_name" {
			return 0, errors.New("no such table")
		}
		return 4, nil
	}
	counts, err := Tally([]string{"scan", "old_name"}, map[string]bool{"scan": true}, ask, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := counts["old_name"]; ok || counts["scan"] != 4 {
		t.Errorf("counts = %v, want scan alone", counts)
	}
}

func TestEveryTableTheReleaseNamesMustBeCounted(t *testing.T) {
	tables, required := releaseCount([]string{"finding", "decision"})
	if !slices.Equal(tables, []string{"finding", "decision"}) {
		t.Errorf("counted %v, want the release's tables", tables)
	}
	for _, table := range tables {
		if !required[table] {
			t.Errorf("%s may go uncounted, so a failed count reads as an absent table", table)
		}
	}
}

func TestAnUpgradeShortOfThisTreeIsAFaultBeforeAnythingIsCounted(t *testing.T) {
	tables, required, fault := upgradedCount(46, 47, []string{"finding"}, []string{"finding", "late"})
	if fault == "" || !strings.Contains(fault, "46") || !strings.Contains(fault, "47") {
		t.Errorf("a short upgrade: fault %q, want one naming both versions", fault)
	}
	if tables != nil || required != nil {
		t.Errorf("a short upgrade counts %v requiring %v, want nothing counted", tables, required)
	}
}

func TestAfterTheUpgradeOnlyThisTreesTablesMustBeCounted(t *testing.T) {
	tables, required, fault := upgradedCount(47, 47, []string{"finding", "old_name"}, []string{"finding", "new_name"})
	if fault != "" {
		t.Fatalf("an upgrade that reached this tree: fault %q, want none", fault)
	}
	slices.Sort(tables)
	if !slices.Equal(tables, []string{"finding", "new_name", "old_name"}) {
		t.Errorf("counted %v, want both releases' tables", tables)
	}
	if !required["finding"] || !required["new_name"] || required["old_name"] {
		t.Errorf("required %v, want this tree's tables alone", required)
	}
}
