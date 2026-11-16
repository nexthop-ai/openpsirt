// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// personV0130 is v0.13.0's declaration of the person table.
//
// The baseline's, with when a sign-in in group-bound mode last judged what
// the person holds against what their groups derive.
func personV0130(t *columnTypes) []string {
	made, indexes, err := pick(accessBaseline(t), "person")
	if err != nil {
		panic(err)
	}
	made = withColumn(made, `"audits_derived_at" `+t.timestamp+` NULL,`,
		`-- When a sign-in in group-bound mode judged the work this person
			-- holds against what their groups derive. Null until the first
			-- sign-in since the switch into group-bound mode, which hands back
			-- what assigned roles let them hold; after it, a sign-in hands
			-- back only when something derived went.
			"groups_judged_at" `+t.timestamp+` NULL,`)
	return append([]string{made}, indexes...)
}

// personJudgedV0130 adds when a sign-in last judged what a person holds.
// v0.12.0 recorded nothing, so every person's next sign-in in group-bound mode
// judges it once.
func personJudgedV0130(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("person", "groups_judged_at")
	if err != nil || present {
		return err
	}
	return u.change(personV0130(u.t), change{table: "person", add: []added{{column: "groups_judged_at"}}})
}
