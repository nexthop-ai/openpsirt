// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import "testing"

// One version spelled two ways is one row, showing the spelling that sorts
// first whichever of the two the database answered with first.
func TestOneVersionSpelledTwoWaysFoldsToTheSpellingThatSortsFirst(t *testing.T) {
	for _, order := range [][]string{{"openssl", "OpenSSL"}, {"OpenSSL", "openssl"}} {
		var fold folder
		for _, display := range order {
			fold.add(7, "openssl", display, "3.0.12")
		}
		rows := fold.folded()
		if len(rows) != 1 {
			t.Fatalf("added as %v, one version folded into %d rows", order, len(rows))
		}
		if rows[0].Display != "OpenSSL" {
			t.Errorf("added as %v, the row shows %q, want %q", order, rows[0].Display, "OpenSSL")
		}
	}
}

// A row is per scan as well as per version, and rows come back in the order
// each was first added.
func TestTheFoldKeepsScansApartAndTheOrderRowsArrivedIn(t *testing.T) {
	var fold folder
	fold.add(2, "zlib", "zlib", "1.3")
	fold.add(1, "zlib", "zlib", "1.3")
	fold.add(2, "curl", "curl", "8.4.0")
	fold.add(2, "zlib", "zlib", "1.3")
	rows := fold.folded()
	var got []string
	for _, row := range rows {
		got = append(got, row.Name)
	}
	if len(rows) != 3 || rows[0].At != 2 || rows[1].At != 1 || rows[2].Name != "curl" {
		t.Errorf("the fold answered %v (%+v)", got, rows)
	}
}
