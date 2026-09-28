// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package weakness

// Known is how many the catalog assigned, for a check that this was read at all.
func Known() int { return len(names) }

// All is every weakness the catalog assigns, for a check that walks them.
//
// A copy, because a map handed out is a map a caller can write to — and what
// this package answers is what somebody else published.
func All() map[string]string {
	out := make(map[string]string, len(names))
	for id, name := range names {
		out[id] = name
	}
	return out
}
