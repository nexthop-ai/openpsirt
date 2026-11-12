// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// receivedStatementV0130 is v0.13.0's declaration of the received VEX
// statement table.
//
// v0.11.0's, with when the publisher made each statement and which newer
// statement of theirs set it aside.
func receivedStatementV0130(t *columnTypes) []string {
	statements := append([]string(nil), declaredV0110(t, "received_vex_statement")...)
	statements[0] = withColumn(statements[0], `"declined_by" `+t.refNull+` NULL,`,
		`-- When the publisher made the statement: its own timestamp, else
			-- its document's. Null where neither states one, so the upload
			-- orders it.
			"said_at" `+t.timestamp+` NULL,
			-- The newer statement from the same publisher about the same
			-- product and issue that set this one aside, which a statement
			-- set aside by a revision of its own document has none of. A
			-- plain reference without a foreign key: statements are never
			-- deleted, so it cannot dangle.
			"overtaken_by" `+t.refNull+` NULL,`)
	return statements
}

// receivedStatementTimedV0130 adds when each statement was made and what
// overtook it. v0.12.0 kept neither, so every statement starts without them
// and is ordered by its upload. Each column is asked for alone: on MySQL and
// MariaDB a stop between two leaves the first added.
func receivedStatementTimedV0130(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, column := range []string{"said_at", "overtaken_by"} {
		present, err := u.hasColumn("received_vex_statement", column)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.change(receivedStatementV0130(u.t), change{table: "received_vex_statement",
			add: []added{{column: column}}}); err != nil {
			return err
		}
	}
	return nil
}
