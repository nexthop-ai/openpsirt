// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"unicode/utf8"
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

func TestAnUpgradeMergingImagesMayHoldFewerOfThemAndFillTheirVersions(t *testing.T) {
	before := Counts{"component": 40, "graph_node": 50, "graph_edge": 60, "finding": 10}
	after := Counts{"component": 30, "graph_node": 45, "graph_edge": 55, "finding": 10, "image_version": 20}
	images := Images{Components: 12, Nodes: 20, Edges: 8}
	if faults := Compare(before, after, Moved(42, images)); len(faults) != 0 {
		t.Errorf("merging images from a release before it was reported: %v", faults)
	}
	if faults := Compare(before, after, Moved(43, images)); len(faults) != 4 {
		t.Errorf("from a release that already merged them, want every moved count reported: %v", faults)
	}
	// More gone than the release held for images, a table grown, and more
	// versions than image nodes.
	wrong := Counts{"component": 27, "graph_node": 51, "graph_edge": 51, "finding": 10, "image_version": 21}
	if faults := Compare(before, wrong, Moved(42, images)); len(faults) != 4 {
		t.Errorf("a merge reaching past the images is reported: want four, got %v", faults)
	}
}

// The reasoning fills one row per distinct text, the recorded ratings one per
// moved flaw, the words in force gain the recorded words where none was and
// nothing for a recorded rating with no word, and the unsourced ratings lose
// what the recorded issues lost.
func TestStoringReasoningAndRecordedRatingsReconcilesExactly(t *testing.T) {
	before := Ratings{
		Unsourced: map[int64]int64{7: 2, 8: 1},
		Sourced:   5,
		InForce:   map[Pair]bool{{9, 1}: true},
		Plain:     2,
		Kept:      1,
	}
	// Issue 8's recorded rating is a score with no word, so nothing is put in
	// force for it.
	after := Ratings{
		Unsourced: map[int64]int64{7: 1, 8: 1},
		Sourced:   5,
		InForce:   map[Pair]bool{{9, 1}: true, {7, 1}: true},
		Recorded:  map[Pair]bool{{7, 1}: true, {9, 1}: true, {8, 2}: false},
	}
	held := Counts{"vulnerability_rating": 8, "issue_rating": 1, "finding": 3}
	upgraded := Counts{"vulnerability_rating": 7, "issue_rating": 2, "finding": 3,
		"statement_text": 4, "recorded_rating": 3}
	moved, faults := Restated(42, Words{Distinct: 4}, before, after)
	if len(faults) != 0 {
		t.Errorf("a faithful move was reported: %v", faults)
	}
	if faults := Compare(held, upgraded, moved); len(faults) != 0 {
		t.Errorf("a faithful move's counts were reported: %v", faults)
	}

	// From a release that already moved them, nothing may move.
	moved, faults = Restated(43, Words{Distinct: 4}, before, after)
	if len(faults) != 0 || len(Compare(held, upgraded, moved)) != 4 {
		t.Errorf("from a release past the move, want every moved count reported: %v %v",
			faults, Compare(held, upgraded, moved))
	}
}

// A count off by one row in either direction is reported for each of the
// four tables, naming the size the move allows.
func TestAMoveOffByARowIsReported(t *testing.T) {
	before := Ratings{Unsourced: map[int64]int64{7: 2}, InForce: map[Pair]bool{}, Plain: 1}
	after := Ratings{Unsourced: map[int64]int64{7: 1}, InForce: map[Pair]bool{{7, 1}: true},
		Recorded: map[Pair]bool{{7, 1}: true}}
	moved, _ := Restated(42, Words{Distinct: 3}, before, after)
	held := Counts{"vulnerability_rating": 2, "issue_rating": 0}
	for name, wrong := range map[string]Counts{
		"more": {"vulnerability_rating": 0, "issue_rating": 2, "statement_text": 4, "recorded_rating": 2},
		"less": {"vulnerability_rating": 2, "issue_rating": 0, "statement_text": 2, "recorded_rating": 0},
	} {
		faults := Compare(held, wrong, moved)
		if len(faults) != 4 {
			t.Errorf("%s: want four faults, got %v", name, faults)
		}
		for _, fault := range faults {
			if !strings.Contains(fault, "the upgrade") {
				t.Errorf("%s: %q does not name what the move allows", name, fault)
			}
		}
	}
}

// What no count shows is reported: an unsourced rating gained, one lost from
// an issue holding no recorded rating, a sourced one lost, and a word in force
// taken away.
func TestARatingMovedOutsideTheRecordedFlawsIsReported(t *testing.T) {
	before := Ratings{
		Unsourced: map[int64]int64{1: 1, 2: 1},
		Sourced:   3,
		InForce:   map[Pair]bool{{4, 1}: true},
	}
	after := Ratings{
		Unsourced: map[int64]int64{1: 2, 3: 0},
		Sourced:   2,
		InForce:   map[Pair]bool{},
		Recorded:  map[Pair]bool{},
	}
	_, faults := Restated(42, Words{}, before, after)
	want := []string{"issue 1 held 1", "issue 2 lost 1", "3 ratings named a publisher", "issue 4 in product 1 is gone"}
	if len(faults) != len(want) {
		t.Fatalf("want %d faults, got %v", len(want), faults)
	}
	for _, each := range want {
		found := false
		for _, fault := range faults {
			if strings.Contains(fault, each) {
				found = true
			}
		}
		if !found {
			t.Errorf("nothing says %q: %v", each, faults)
		}
	}
}

// Reasoning is kept as the upgrade stores it: text differing only in trailing
// spaces is two texts, a NUL is dropped, invalid UTF-8 is replaced, and text
// past the bound is cut on a character boundary.
func TestReasoningIsKeptByteForByteAsTheUpgradeStoresIt(t *testing.T) {
	if KeptWords("fixed") == KeptWords("fixed ") {
		t.Error("text differing in a trailing space was kept as one")
	}
	if got := KeptWords("fi\x00xed"); got != "fixed" {
		t.Errorf("a NUL was kept: %q", got)
	}
	if got := KeptWords("a\xffb"); got != "a\uFFFDb" {
		t.Errorf("invalid UTF-8 was kept as %q", got)
	}
	long := strings.Repeat("a", mostWords-1) + "é" + "tail"
	got := KeptWords(long)
	if got != strings.Repeat("a", mostWords-1) {
		t.Errorf("text past the bound was cut to %d bytes, ending %q", len(got), got[len(got)-4:])
	}
	if !utf8.ValidString(got) {
		t.Error("the cut split a character")
	}
	if got := KeptWords(strings.Repeat("a", mostWords)); len(got) != mostWords {
		t.Errorf("text at the bound was cut to %d bytes", len(got))
	}
}
