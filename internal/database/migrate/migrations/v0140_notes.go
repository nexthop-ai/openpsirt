// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// notesColumnV0140 is the status notes a claim gives, declared alike on a
// build's own claims and on a received statement.
const notesColumnV0140 = `-- The status notes the claim gives, stored once however many
			-- subjects its statement names, beside the reasoning and never in
			-- its place. Null where it gave none. A plain reference without a
			-- foreign key: stored words are never deleted, so the reference
			-- cannot dangle.
			"notes_id" `

// suppressionV0140 is v0.14.0's declaration of a build's own claims: v0.11.0's,
// with the status notes each claim gives.
func suppressionV0140(t *columnTypes) []string {
	statements := append([]string(nil), declaredV0110(t, "suppression")...)
	statements[0] = withColumn(statements[0], `"statement_id" `+t.refNull+` NULL,`,
		notesColumnV0140+t.refNull+` NULL,`)
	return statements
}

// receivedStatementV0140 is v0.14.0's declaration of the received VEX
// statement table: v0.13.0's, with the status notes each statement gives.
func receivedStatementV0140(t *columnTypes) []string {
	statements := append([]string(nil), receivedStatementV0130(t)...)
	statements[0] = withColumn(statements[0], `"statement_id" `+t.refNull+` NULL,`,
		notesColumnV0140+t.refNull+` NULL,`)
	return statements
}

// statementNotesV0140 adds the status notes column to both tables. v0.13.0
// kept no notes, so every claim and statement starts without them. Each table
// is asked alone: on MySQL and MariaDB a stop between the two leaves the first
// added.
func statementNotesV0140(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, each := range []struct {
		table    string
		declared []string
	}{
		{"suppression", suppressionV0140(u.t)},
		{"received_vex_statement", receivedStatementV0140(u.t)},
	} {
		present, err := u.hasColumn(each.table, "notes_id")
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.change(each.declared, change{table: each.table,
			add: []added{{column: "notes_id"}}}); err != nil {
			return err
		}
	}
	return nil
}
