// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

// vulnerabilityV0110 is v0.11.0's declaration of the vulnerability table.
//
// The baseline's, with what sort of issue each row is. Derived from the
// baseline's declaration; no release between changed it.
func vulnerabilityV0110(t *columnTypes) []string {
	made, indexes, err := pick(vulnerabilityBaseline(t), "vulnerability")
	if err != nil {
		panic(err)
	}
	made = withColumn(made, `"identifier_folded" `+t.name+` NOT NULL,`,
		`-- What sort of issue this is: a published vulnerability, a flaw
			-- minted here, or an analyzer's rule. A name is resolved among
			-- issues of the sorts its producer files under, so a rule never
			-- merges with a CVE.
			"kind"          `+t.kind+` NOT NULL,`)
	return append([]string{made}, indexes...)
}

// issueKindV0110 adds what sort of issue each row is. An issue holding a
// finding somebody recorded here is a flaw minted here, and every other is a
// published vulnerability: v0.10.0 held no rule. Stepped over where a start
// that stopped after adding it finds it there, which MySQL and MariaDB leave
// behind.
func issueKindV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if present, err := u.hasColumn("vulnerability", "kind"); err != nil || present {
		return err
	}
	return u.change(vulnerabilityV0110(u.t), change{table: "vulnerability",
		add: []added{{column: "kind", fill: `'vulnerability'`}},
		then: func() error {
			if _, err := tx.ExecContext(ctx, `UPDATE "vulnerability" SET "kind" = 'flaw'
				WHERE EXISTS (SELECT 1 FROM "finding" AS "f"
					WHERE "f"."vulnerability_id" = "vulnerability"."id" AND "f"."kind" = 'entered')`); err != nil {
				return fmt.Errorf("mark the flaws recorded here: %w", err)
			}
			return nil
		}})
}
