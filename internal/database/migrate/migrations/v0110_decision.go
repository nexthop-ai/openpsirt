// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// decisionStampV0110 is v0.11.0's declaration of the stamp each decision's
// writers match on.
func decisionStampV0110(t *columnTypes) []string {
	return []string{
		// Changed by a lead's hand-off resting on the decision, and by
		// revising, withdrawing, approving, setting aside, sending back or
		// undoing the approval of it, each matching the value it read. A write
		// matching none lost a race with another and is taken again, so a
		// hand-off and a withdrawal of the decision it rests on cannot both
		// commit. A decision with no row here holds the stamp zero.
		//
		// A row of its own, which no foreign key points at: InnoDB locks
		// the parent row of every child it checks, so a stamp on the decision
		// row waits on any transaction that inserted a row naming the
		// decision.
		`CREATE TABLE "decision_stamp" (
			"decision_id"    ` + t.ref + ` NOT NULL,
			"stamp"          INTEGER NOT NULL,
			CONSTRAINT "decision_stamp_pk" PRIMARY KEY ("decision_id"),
			CONSTRAINT "decision_stamp_decision_fk" FOREIGN KEY ("decision_id") REFERENCES "decision"("id")
		)` + t.suffix,
	}
}

// createDecisionStampV0110 makes the table of decision stamps. Every decision
// v0.10.0 held starts at zero, which is no row. Stepped over where it is
// already there.
func createDecisionStampV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if present, err := u.hasColumn("decision_stamp", "decision_id"); err != nil || present {
		return err
	}
	return u.create(decisionStampV0110(u.t), "decision_stamp")
}
