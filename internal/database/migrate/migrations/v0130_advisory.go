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

// advisoryIssueV0130 is v0.13.0's declaration of the advisory_issue table.
//
// v0.12.0's, with a mark held while the issue is on the advisory, and the
// issue unique on the advisory among the rows holding it.
func advisoryIssueV0130(t *columnTypes) []string {
	made, indexes, err := pick(advisoryBaseline(t), "advisory_issue")
	if err != nil {
		panic(err)
	}
	for _, edit := range []struct{ from, to string }{
		{`			-- Taken back off, by whom. The row stays so that the act has
			-- somewhere to be written: deleted, who removed an issue from an
			-- advisory is a question nothing answers. Adding it again revives
			-- this row rather than writing a second one, which is what keeps
			-- the pair unique.
`, `			-- Taken back off, by whom. The row stays so that the act has
			-- somewhere to be written: deleted, who removed an issue from an
			-- advisory is a question nothing answers. Adding it again writes
			-- another row, so each stretch an issuance may have named it in
			-- is kept.
`},
		{`			"removed_by"       ` + t.refNull + ` NULL,
`, `			"removed_by"       ` + t.refNull + ` NULL,
			-- True while the issue is on the advisory and null once taken
			-- off. Nulls are distinct under a uniqueness rule on all four
			-- engines, so the rule below holds among the rows on the advisory
			-- alone.
			"live"             ` + t.boolean + ` NULL,
`},
		{`			CONSTRAINT "advisory_issue_once"
				UNIQUE ("advisory_id", "product_id", "vulnerability_id"),
`, `			CONSTRAINT "advisory_issue_live_once"
				UNIQUE ("advisory_id", "product_id", "vulnerability_id", "live"),
`},
	} {
		if !strings.Contains(made, edit.from) {
			panic("v0.12.0's declaration of advisory_issue holds no " + firstLine(edit.from))
		}
		made = strings.Replace(made, edit.from, edit.to, 1)
	}
	return append([]string{made}, indexes...)
}

// advisoryCoverLiveV0130 adds the mark an issue on an advisory holds, sets it
// on every row still on one, and moves the uniqueness rule onto it.
//
// The rule holding the mark is made before the one it replaces is dropped:
// MySQL and MariaDB hold the advisory's foreign key on an index led by its
// column, and refuse to drop the last one. Each piece is asked for alone, so
// a start that stopped between two makes what is missing.
func advisoryCoverLiveV0130(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	declared := advisoryIssueV0130(u.t)
	mark := func() error {
		if _, err := tx.NewUpdate().TableExpr(`"advisory_issue"`).
			Set(`"live" = ?`, true).
			Where(`"removed_at" IS NULL`).Where(`"live" IS NULL`).
			Exec(ctx); err != nil {
			return fmt.Errorf("mark the issues still on an advisory: %w", err)
		}
		return nil
	}
	present, err := u.hasColumn("advisory_issue", "live")
	if err != nil {
		return err
	}
	if !present {
		// SQLite rebuilds the table from the declaration, which holds the
		// new rule and not the old one.
		if err := u.change(declared, change{table: "advisory_issue",
			add: []added{{column: "live"}}, then: mark,
			constraints: []string{"advisory_issue_live_once"}}); err != nil {
			return err
		}
	} else if u.engine != database.SQLite {
		if err := mark(); err != nil {
			return err
		}
		held, err := u.hasIndex("advisory_issue", "advisory_issue_live_once")
		if err != nil {
			return err
		}
		if !held {
			if err := u.change(declared, change{table: "advisory_issue",
				constraints: []string{"advisory_issue_live_once"}}); err != nil {
				return err
			}
		}
	}
	if u.engine == database.SQLite {
		return nil
	}
	old, err := u.hasIndex("advisory_issue", "advisory_issue_once")
	if err != nil || !old {
		return err
	}
	if u.engine == database.Postgres {
		return u.run([]string{`ALTER TABLE "advisory_issue" DROP CONSTRAINT "advisory_issue_once"`})
	}
	return dropIndex(ctx, u.raw, "advisory_issue", "advisory_issue_once")
}
