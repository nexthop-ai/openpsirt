// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// TablesRenamedV0110 is every table the v0.11.0 upgrade renames, from its
// v0.10.0 name to its v0.11.0 one. A table is renamed once, so no name in it
// is renamed again: v0.10.0's "decision" is v0.11.0's "decision_occurrence",
// and its "claim" is v0.11.0's "decision".
func TablesRenamedV0110() map[string]string {
	out := make(map[string]string, len(tablesRenamedV0110))
	for _, r := range tablesRenamedV0110 {
		out[r.from] = r.to
	}
	return out
}
