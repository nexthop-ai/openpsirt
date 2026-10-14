// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"slices"
)

// Counts is how many rows each table holds.
type Counts map[string]int64

// Movement is what an upgrade may do to a table's count from the rows the
// release held.
type Movement int

const (
	// Fills is a new table the upgrade writes from rows the release held.
	Fills Movement = iota + 1
	// Merges is a table the upgrade merges rows of, which may hold fewer.
	Merges
)

// imagesByName is the migration that identifies a container image by its
// name: it merges the components, nodes and edges a release made per version
// of one image, and records each version a build stated from those nodes.
const imagesByName = 43

// Moved is what the upgrade from a release whose last migration is given may
// do to each table's count, beyond keeping it.
func Moved(fromLast int64) map[string]Movement {
	moved := map[string]Movement{}
	if fromLast < imagesByName {
		moved["image_version"] = Fills
		moved["component"] = Merges
		moved["graph_node"] = Merges
		moved["graph_edge"] = Merges
	}
	return moved
}

// Compare reports every table whose count moved across an upgrade. before is
// what the release held, after is what the upgrade left. A table both sides
// hold keeps its count, and a table only the upgrade holds starts empty,
// except as moved says.
func Compare(before, after Counts, moved map[string]Movement) []string {
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
		case held && moved[name] == Merges && is <= was && (is > 0 || was == 0):
		case held && is != was:
			faults = append(faults, fmt.Sprintf("%s held %d rows and holds %d", name, was, is))
		case !held && moved[name] == Fills:
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
