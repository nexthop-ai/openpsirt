// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

package migrations

// NotificationKindsRenamedV0110 is every notification kind v0.11.0 renames,
// by its v0.10.0 name.
func NotificationKindsRenamedV0110() []string {
	var out []string
	for _, v := range valuesRewrittenV0110 {
		if v.table == "notification" && v.column == "kind" {
			out = append(out, v.from)
		}
	}
	return out
}
