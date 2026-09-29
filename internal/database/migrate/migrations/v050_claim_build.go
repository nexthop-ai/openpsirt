// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// claimBuildV050 is v0.5.0's declaration of the builds a claim was made on.
//
// New in v0.5.0. A decision is keyed without a build and reaches every build
// whose versions match, so this is the only record of which builds somebody was
// looking at when they made it: the one on screen, and every one they chose
// beside it. A build the claim reaches by lookup is never recorded.
func claimBuildV050(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "claim_build" (
			"id"        ` + t.id + `,
			"claim_id"  ` + t.ref + ` NOT NULL,
			"target_id" ` + t.ref + ` NOT NULL,
			CONSTRAINT "claim_build_once" UNIQUE ("claim_id", "target_id"),
			CONSTRAINT "claim_build_claim_fk" FOREIGN KEY ("claim_id") REFERENCES "claim"("id"),
			CONSTRAINT "claim_build_target_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id")
		)` + t.suffix,
	}
}
