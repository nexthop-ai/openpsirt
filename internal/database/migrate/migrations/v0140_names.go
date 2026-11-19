// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// ComponentNamesV0140 is the migration that makes the component name table
// and fills it from every component.
const ComponentNamesV0140 = 48

// NamesV0140 is how many names the v0.14.0 upgrade keeps for a component with
// this package identifier and folded name: the folded name, and the one its
// package identifier gives where that differs. A rehearsal works out the
// table's fill from it against the release's own rows.
func NamesV0140(purl, folded string) int64 {
	var n int64
	if folded != "" {
		n++
	}
	if apart := foldedV0130(packageNameV0140(purl)); apart != "" && apart != folded {
		n++
	}
	return n
}
