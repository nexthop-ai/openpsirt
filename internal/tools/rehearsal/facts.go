// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"slices"
)

// Counts is how many rows each table holds.
type Counts map[string]int64

// kind is what a table's count may do across an upgrade.
type kind int

const (
	// same is the default for a table both sides hold: an upgrade moves no
	// row in or out of it.
	same kind = iota
	// equal is a table the upgrade fills from another: it holds as many rows
	// as the other held before.
	equal
	// atMost is a table the upgrade fills with at most one row per row of
	// another. An advisory is one per product and issue that was issued
	// about, so several issuances can share one.
	atMost
	// gone is a table the upgrade removes after moving its rows elsewhere.
	gone
)

// expect is the rule for one table.
type expect struct {
	kind kind
	of   string
}

// rules is what the upgrade tables in the database design document say
// happens to the rows of a release carried to this tree. A table no rule
// names keeps its rows when both sides hold it, and starts empty when only
// the upgraded side does.
func rules(from string) map[string]expect {
	switch from {
	case "v0.1.0":
		return map[string]expect{
			// An embargo extension is a disclosure movement whose act is an
			// extension, under the same identifier.
			"disclosure_extension": {kind: gone},
			"disclosure_movement":  {kind: equal, of: "disclosure_extension"},
			// An issuance keyed on a product and an issue becomes an advisory
			// per product and issue, with one edition and the one issue it
			// covers. Its issuances keep their rows.
			"advisory":         {kind: atMost, of: "advisory_issuance"},
			"advisory_edition": {kind: atMost, of: "advisory_issuance"},
			"advisory_issue":   {kind: atMost, of: "advisory_issuance"},
		}
	}
	return nil
}

// Compare reports every table whose count after an upgrade is not what the
// rules allow. before is what the release held, after is what the upgrade
// left; a table the rules do not name keeps its count, or starts empty where
// the release did not have it.
func Compare(before, after Counts, rules map[string]expect) []string {
	var faults []string
	names := map[string]bool{}
	for name := range before {
		names[name] = true
	}
	for name := range after {
		names[name] = true
	}
	for name := range rules {
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
		rule, ruled := rules[name]
		switch {
		case ruled && rule.kind == gone:
			if holds {
				faults = append(faults, fmt.Sprintf("%s is still there, and the upgrade removes it", name))
			}
		case ruled && rule.kind == equal:
			if want := before[rule.of]; is != want {
				faults = append(faults, fmt.Sprintf("%s holds %d rows, and the upgrade makes one for each of the %d in %s",
					name, is, want, rule.of))
			}
		case ruled && rule.kind == atMost:
			if limit := before[rule.of]; is > limit || (limit > 0 && is == 0) {
				faults = append(faults, fmt.Sprintf("%s holds %d rows, and the upgrade makes between one and %d from %s",
					name, is, limit, rule.of))
			}
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
