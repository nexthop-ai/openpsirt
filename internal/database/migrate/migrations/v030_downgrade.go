// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// downgradeV030 puts back the schema v0.2.0 built, by taking away the three
// columns the upgrade added and what they held.
//
// A deadline and a disclosure date the upgrade moved stay where it moved
// them. v0.2.0 reads both columns as it always did, and what they held before
// is not kept.
//
// The settings the upgrade carried stay carried. The disclosure movement
// threshold is under the name v0.2.0 reads. The patch branch switch is not put
// back, because the upgrade kept nothing saying what it was, so v0.2.0 has
// the lookups off until somebody turns them on again.
func downgradeV030(ctx context.Context, tx bun.Tx) error {
	return apply(ctx, tx.Tx, []string{
		`ALTER TABLE "flaw_report" DROP COLUMN "found_here"`,
		`ALTER TABLE "component" DROP COLUMN "license"`,
		`ALTER TABLE "finding" DROP COLUMN "rated_at"`,
	})
}
