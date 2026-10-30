// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"slices"
)

// Counts is how many rows each table holds.
type Counts map[string]int64

// renamesV0110 is the migration that gives tables the names the interface
// uses.
const renamesV0110 = 45

// AsRenamed is the counts a release held, each under the name the upgrade
// from a release whose last migration is given leaves its table with. renamed
// maps a table's name before the upgrade to its name after; a table it does
// not name keeps its name, and no name is renamed twice.
func AsRenamed(fromLast int64, held Counts, renamed map[string]string) Counts {
	if fromLast >= renamesV0110 {
		return held
	}
	out := make(Counts, len(held))
	for name, n := range held {
		if to, ok := renamed[name]; ok {
			name = to
		}
		out[name] = n
	}
	return out
}

// FilledV0110 is the rows the upgrade from a release whose last migration is
// given writes from what the release held: each acknowledgement it recorded
// becomes a report's first message sent. A release already past that upgrade
// has its messages and is filled with nothing.
func FilledV0110(fromLast, acknowledged int64) Counts {
	if fromLast >= renamesV0110 {
		return Counts{}
	}
	return Counts{"report_message": acknowledged}
}

// Compare reports every table whose count moved across an upgrade. before is
// what the release held, after is what the upgrade left, and filled is the
// rows the upgrade writes into a table from what the release held elsewhere. A
// table holds what it held and what it is filled with, and a table only the
// upgrade holds starts with what it is filled with and nothing more.
func Compare(before, after, filled Counts) []string {
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
		case held && is != was+filled[name]:
			faults = append(faults, fmt.Sprintf("%s held %d rows, is filled with %d, and holds %d", name, was, filled[name], is))
		case !held && is != filled[name] && filled[name] == 0:
			faults = append(faults, fmt.Sprintf("%s is new and holds %d rows, and nothing the release held fills it", name, is))
		case !held && is != filled[name]:
			faults = append(faults, fmt.Sprintf("%s is new and holds %d rows, and what the release held fills it with %d", name, is, filled[name]))
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
