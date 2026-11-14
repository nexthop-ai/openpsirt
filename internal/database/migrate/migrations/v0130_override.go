// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// advisoryOverrideV0130 is v0.13.0's declaration of the advisory_override
// table.
//
// v0.12.0's, with a mark held while the release is marked, and the release
// marked once on the advisory among the rows holding it.
func advisoryOverrideV0130(t *columnTypes) []string {
	declared := declaredV0110(t, "advisory_override")
	made := declared[0]
	for _, edit := range []struct{ from, to string }{
		{`			-- Cleared, by whom. The row stays so that the act has somewhere to
			-- be written, and marking the release again revives it, which is
			-- what keeps the release marked once.
`, `			-- Cleared, by whom. The row stays so that the act has somewhere to
			-- be written. Marking the release again writes another row, so who
			-- marked and cleared it each time is kept.
`},
		{`			"removed_by"       ` + t.refNull + ` NULL,
`, `			"removed_by"       ` + t.refNull + ` NULL,
			-- True while the release is marked and null once cleared. Nulls
			-- are distinct under a uniqueness rule on all four engines, so the
			-- rule below holds among the rows marking it alone.
			"live"             ` + t.boolean + ` NULL,
`},
		{`			CONSTRAINT "advisory_override_once" UNIQUE
				("advisory_id", "product_id", "vulnerability_id", "branch_or_tag_id", "variant_id"),
`, `			CONSTRAINT "advisory_override_live_once" UNIQUE
				("advisory_id", "product_id", "vulnerability_id", "branch_or_tag_id", "variant_id", "live"),
`},
	} {
		if !strings.Contains(made, edit.from) {
			panic("v0.12.0's declaration of advisory_override holds no " + firstLine(edit.from))
		}
		made = strings.Replace(made, edit.from, edit.to, 1)
	}
	return append([]string{made}, declared[1:]...)
}

// advisoryOverrideLiveV0130 adds the mark a release an advisory marks
// affected holds, sets it on every row still marking one, and moves the
// uniqueness rule onto it.
//
// The rule holding the mark is made before the one it replaces is dropped:
// MySQL and MariaDB hold the advisory's foreign key on an index led by its
// column, and refuse to drop the last one. Each piece is asked for alone, so
// a start that stopped between two makes what is missing.
func advisoryOverrideLiveV0130(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	declared := advisoryOverrideV0130(u.t)
	mark := func() error {
		if _, err := tx.NewUpdate().TableExpr(`"advisory_override"`).
			Set(`"live" = ?`, true).
			Where(`"removed_at" IS NULL`).Where(`"live" IS NULL`).
			Exec(ctx); err != nil {
			return fmt.Errorf("mark the releases still marked affected: %w", err)
		}
		return nil
	}
	present, err := u.hasColumn("advisory_override", "live")
	if err != nil {
		return err
	}
	if !present {
		// SQLite rebuilds the table from the declaration, which holds the
		// new rule and not the old one.
		if err := u.change(declared, change{table: "advisory_override",
			add: []added{{column: "live"}}, then: mark,
			constraints: []string{"advisory_override_live_once"}}); err != nil {
			return err
		}
	} else if u.engine != database.SQLite {
		if err := mark(); err != nil {
			return err
		}
		held, err := u.hasIndex("advisory_override", "advisory_override_live_once")
		if err != nil {
			return err
		}
		if !held {
			if err := u.change(declared, change{table: "advisory_override",
				constraints: []string{"advisory_override_live_once"}}); err != nil {
				return err
			}
		}
	}
	if u.engine == database.SQLite {
		return nil
	}
	old, err := u.hasIndex("advisory_override", "advisory_override_once")
	if err != nil || !old {
		return err
	}
	if u.engine == database.Postgres {
		return u.run([]string{`ALTER TABLE "advisory_override" DROP CONSTRAINT "advisory_override_once"`})
	}
	return dropIndex(ctx, u.raw, "advisory_override", "advisory_override_once")
}
