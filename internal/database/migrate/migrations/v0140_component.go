// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// componentV0140 is v0.14.0's declaration of the component table.
//
// v0.13.0's, with what the inventory says the component is.
func componentV0140(t *columnTypes) []string {
	statements := append([]string(nil), componentV0130(t)...)
	statements[0] = withColumn(statements[0], `"license"            `+t.free+` NULL,`,
		`-- What the inventory says the component is, as one line cut to
			-- the width of an index's summary. Shown where no index gave a
			-- summary. Absent where no inventory said.
			"description"        `+t.free+` NULL,`)
	return statements
}

// componentDescriptionV0140 adds the column holding what the inventory says a
// component is. v0.13.0 kept none, so every component starts without one, and
// the next inventory stating one fills it.
func componentDescriptionV0140(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("component", "description")
	if err != nil || present {
		return err
	}
	return u.change(componentV0140(u.t), change{table: "component",
		add: []added{{column: "description"}}})
}
