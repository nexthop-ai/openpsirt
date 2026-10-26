// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// claimStampV0110 is v0.11.0's declaration of the stamp each claim's writers
// match on.
func claimStampV0110(t *columnTypes) []string {
	return []string{
		// Changed by a lead's hand-off resting on the claim, and by revising,
		// withdrawing, approving, setting aside, sending back or undoing the
		// approval of it, each matching the value it read. A write
		// matching none lost a race with another and is taken again, so a
		// hand-off and a withdrawal of the claim it rests on cannot both
		// commit. A claim with no row here holds the stamp zero.
		//
		// A row of its own, which no foreign key points at: InnoDB locks
		// the parent row of every child it checks, so a stamp on the claim
		// row waits on any transaction that inserted a row naming the claim.
		`CREATE TABLE "claim_stamp" (
			"claim_id"       ` + t.ref + ` NOT NULL,
			"stamp"          INTEGER NOT NULL,
			CONSTRAINT "claim_stamp_pk" PRIMARY KEY ("claim_id"),
			CONSTRAINT "claim_stamp_claim_fk" FOREIGN KEY ("claim_id") REFERENCES "claim"("id")
		)` + t.suffix,
	}
}

// createClaimStampV0110 makes the table of claim stamps. Every claim v0.10.0
// held starts at zero, which is no row. Stepped over where it is already
// there.
func createClaimStampV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if present, err := u.hasColumn("claim_stamp", "claim_id"); err != nil || present {
		return err
	}
	return u.create(claimStampV0110(u.t), "claim_stamp")
}
