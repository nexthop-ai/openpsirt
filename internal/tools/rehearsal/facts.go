// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"slices"
)

// Counts is how many rows each table holds.
type Counts map[string]int64

// seededTables are the tables a release's seed has to leave rows in for an
// upgrade of it to check anything.
var seededTables = []string{"finding", "decision", "decision_occurrence", "received_vex_statement", "flaw_report"}

// Unseeded is every table a release's seed left empty.
func Unseeded(held Counts) []string {
	var empty []string
	for _, table := range seededTables {
		if held[table] == 0 {
			empty = append(empty, table)
		}
	}
	return empty
}

// Compare reports every table whose count moved across an upgrade. before is
// what the release held and after is what the upgrade left. A table holds
// what it held, and a table only the upgrade holds is empty.
func Compare(before, after Counts) []string {
	var faults []string
	names := map[string]bool{}
	for name := range before {
		names[name] = true
	}
	for name := range after {
		names[name] = true
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	slices.Sort(ordered)

	for _, name := range ordered {
		was, held := before[name]
		is, holds := after[name]
		switch {
		case held && !holds:
			faults = append(faults, fmt.Sprintf("%s held %d rows and is gone, and nothing says where they went", name, was))
		case held && is != was:
			faults = append(faults, fmt.Sprintf("%s held %d rows and holds %d", name, was, is))
		case !held && is != 0:
			faults = append(faults, fmt.Sprintf("%s is new and holds %d rows, and nothing the release held fills it", name, is))
		}
	}
	return faults
}

// Totals is a number the interface shows for each build, keyed on the build.
type Totals map[string]int64

// CompareTotals reports every build whose total moved, and every build one
// side names and the other does not.
func CompareTotals(what string, before, after Totals) []string {
	var faults []string
	keys := make([]string, 0, len(before)+len(after))
	for key := range before {
		keys = append(keys, key)
	}
	for key := range after {
		if _, ok := before[key]; !ok {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	for _, key := range keys {
		was, held := before[key]
		is, holds := after[key]
		switch {
		case !holds:
			faults = append(faults, fmt.Sprintf("%s: %s read %d before and is not answered after", what, key, was))
		case !held:
			faults = append(faults, fmt.Sprintf("%s: %s is answered after and was not before", what, key))
		case was != is:
			faults = append(faults, fmt.Sprintf("%s: %s read %d before and %d after", what, key, was, is))
		}
	}
	return faults
}

// Tally counts each table through ask. A table in required that cannot be
// counted is an error naming it, because an uncounted table reads as absent
// and Compare passes a table emptied by the upgrade it never saw held. Any
// other table that cannot be counted is one the side does not hold, and is
// left out of the answer.
func Tally(tables []string, required map[string]bool, ask func(table string) (int64, error), log io.Writer) (Counts, error) {
	counts := Counts{}
	for _, table := range tables {
		n, err := ask(table)
		if err != nil {
			if required[table] {
				return nil, fmt.Errorf("count %s: %w", table, err)
			}
			_, _ = fmt.Fprintf(log, "count %s: %v\n", table, err)
			continue
		}
		counts[table] = n
	}
	return counts, nil
}
