// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// v010GroupIndex is the grouping index as v0.1.0 declared it, before a finding
// could be exploited here.
const v010GroupIndex = `CREATE INDEX "finding_group_idx" ON "finding" ("target_id", "closed_at", "visibility", "vulnerability_id", "component_id", "urgency")`

// downgradeV020 changes v0.2.0's schema back into v0.1.0's.
//
// Rows v0.1.0 has no place for go with the tables and columns that held them:
// an embargo shortened, a report that did not become an issue, judged or not,
// a file attached to a report, the second and later issues an advisory covers,
// and every later advisory about the same issue in the same product.
func downgradeV020(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}

	steps := []func() error{
		u.returnAdvisories,
		u.returnDisclosures,
		func() error { return dropTables(ctx, u.raw, "report_ruled") },
		func() error {
			return u.narrow(narrowing{table: "attachment",
				forget:  `DELETE FROM "attachment" WHERE "vulnerability_id" IS NULL`,
				indexes: []string{"attachment_report_idx"}, keys: []string{"attachment_report_fk"},
				columns: []string{"flaw_report_id"}, require: []string{"vulnerability_id"}})
		},
		func() error {
			return u.narrow(narrowing{table: "flaw_report",
				forget:  `DELETE FROM "flaw_report" WHERE "vulnerability_id" IS NULL`,
				indexes: []string{"flaw_report_product_idx", "flaw_report_ruling_idx"},
				// v0.1.0's product key had an index of its own on MySQL and
				// MariaDB, which each makes for a key no index serves, and
				// v0.2.0's product index took its place.
				rekey:   []string{"flaw_report_product_fk"},
				keys:    []string{"flaw_report_answered_by_fk", "flaw_report_judged_by_fk", "flaw_report_ruling_fk"},
				columns: []string{"reference", "summary", "evaluated_at", "evaluated_by", "ruling_id", "found_here"},
				require: []string{"vulnerability_id"}})
		},
		func() error {
			return u.narrow(narrowing{table: "vex_statement", indexes: []string{"vex_statement_from_idx"},
				columns: []string{"source", "document_id", "about"}})
		},
		func() error { return u.narrow(narrowing{table: "notification", columns: []string{"together"}}) },
		func() error {
			return u.narrow(narrowing{table: "finding", indexes: []string{"finding_group_idx"},
				columns: []string{"urgency_exploited_here", "rated_at"}, restore: []string{v010GroupIndex}})
		},
		func() error {
			return u.narrow(narrowing{table: "vulnerability_weakness", columns: []string{"is_primary"}})
		},
		func() error { return u.narrow(narrowing{table: "scan", columns: []string{"root_identifier"}}) },
		func() error { return u.narrow(narrowing{table: "variant", columns: []string{"retired_at"}}) },
		func() error { return u.narrow(narrowing{table: "stream", columns: []string{"retired_at"}}) },
		func() error {
			return u.narrow(narrowing{table: "product", columns: []string{"pair_share", "pair_approvers", "retired_at"}})
		},
		func() error {
			return dropTables(ctx, u.raw, "patch_commit_branch", "patch_commit", "patch_repository",
				"advisory_source", "told_outside", "obligation_window_product", "obligation_window",
				"exploited_here", "vex_issuance", "report_ruling", "vulnerability_rating")
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// narrowing is what one table gives back.
type narrowing struct {
	table string
	// forget deletes the rows v0.1.0 cannot hold, before a column refuses a
	// null again.
	forget string
	// keys and indexes are dropped first, then columns. require is the
	// columns that refuse a null again, and restore the indexes put back as
	// v0.1.0 declared them.
	indexes []string
	keys    []string
	columns []string
	require []string
	restore []string
	// rekey is the keys MySQL and MariaDB serve with an index being dropped.
	// Each is dropped and declared again around it, so the engine makes the
	// key an index of its own the way it did in v0.1.0: one made by hand is
	// kept when v0.2.0's index arrives, and one the engine made is not.
	rekey []string
}

func (u *upgrader) narrow(n narrowing) error {
	if n.forget != "" {
		if _, err := u.tx.ExecContext(u.ctx, n.forget); err != nil {
			return fmt.Errorf("remove what %s cannot hold: %w", n.table, err)
		}
	}
	if u.engine == database.SQLite {
		return u.narrowSQLite(n)
	}

	// Keys before indexes: MySQL and MariaDB refuse to drop an index a
	// foreign key is using.
	rekey := n.rekey
	if u.engine == database.Postgres {
		rekey = nil
	}
	for _, name := range append(slices.Clone(n.keys), rekey...) {
		if err := u.dropKey(n.table, name); err != nil {
			return err
		}
	}
	for _, name := range n.indexes {
		if err := dropIndex(u.ctx, u.raw, n.table, name); err != nil {
			return err
		}
	}
	if len(rekey) > 0 {
		declared, err := u.liveDeclaration(n.table)
		if err != nil {
			return err
		}
		var again []string
		for _, name := range rekey {
			def, err := declared.constraint(name)
			if err != nil {
				return err
			}
			again = append(again, `ALTER TABLE "`+n.table+`" ADD `+def)
		}
		if err := u.run(again); err != nil {
			return err
		}
	}
	var stmts []string
	for _, column := range n.columns {
		stmts = append(stmts, `ALTER TABLE "`+n.table+`" DROP COLUMN "`+column+`"`)
	}
	if len(n.require) > 0 {
		declared, err := u.liveDeclaration(n.table)
		if err != nil {
			return err
		}
		for _, column := range n.require {
			switch u.engine {
			case database.Postgres:
				stmts = append(stmts, `ALTER TABLE "`+n.table+`" ALTER COLUMN "`+column+`" SET NOT NULL`)
			default:
				def, err := declared.column(column)
				if err != nil {
					return err
				}
				stmts = append(stmts, `ALTER TABLE "`+n.table+`" MODIFY COLUMN `+refusingNull(def))
			}
		}
	}
	stmts = append(stmts, n.restore...)
	return u.run(stmts)
}

// dropKey drops a foreign key. MySQL and MariaDB keep the index they made
// for it, which v0.1.0 did not have, so that goes too where it is there.
func (u *upgrader) dropKey(table, name string) error {
	if u.engine == database.Postgres {
		return u.run([]string{`ALTER TABLE "` + table + `" DROP CONSTRAINT "` + name + `"`})
	}
	if err := u.run([]string{`ALTER TABLE "` + table + `" DROP FOREIGN KEY "` + name + `"`}); err != nil {
		return err
	}
	left, err := u.hasIndex(table, name)
	if err != nil || !left {
		return err
	}
	return dropIndex(u.ctx, u.raw, table, name)
}

// liveDeclaration is v0.2.0's declaration of a table, which is where a
// server's column spelling is read from: the database reports types in its
// own words, which are not always the words it accepts back.
func (u *upgrader) liveDeclaration(table string) (*declaration, error) {
	for _, statements := range [][]string{attachmentStatements(u.t), reportStatements(u.t)} {
		if made, _, err := pick(statements, table); err == nil {
			return declared(made)
		}
	}
	return nil, fmt.Errorf("%s has no declaration here", table)
}

// refusingNull turns a column that takes a null into one that does not.
func refusingNull(def string) string {
	return strings.TrimSuffix(def, " NULL") + " NOT NULL"
}

// narrowSQLite rebuilds a table from the statement SQLite holds for it, with
// what v0.2.0 added taken out. The statement is the one the upgrade created
// the table with, or the release's own where the upgrade only added a column.
func (u *upgrader) narrowSQLite(n narrowing) error {
	var made string
	if err := u.raw.QueryRowContext(u.ctx,
		`SELECT "sql" FROM "sqlite_master" WHERE "type" = 'table' AND "name" = ?`, n.table).Scan(&made); err != nil {
		return fmt.Errorf("read how %s is declared: %w", n.table, err)
	}
	d, err := declared(made)
	if err != nil {
		return err
	}
	gone := map[string]bool{}
	for _, c := range n.columns {
		gone[c] = true
	}
	required := map[string]bool{}
	for _, c := range n.require {
		required[c] = true
	}
	var items, kept []string
	for _, column := range d.columns {
		if gone[column] {
			continue
		}
		def := d.definitions[column]
		if required[column] {
			def = refusingNull(def)
		}
		items = append(items, def)
		kept = append(kept, `"`+column+`"`)
	}
	for name, def := range d.constraints {
		if !mentionsAny(def, gone) && !slices.Contains(n.keys, name) {
			items = append(items, def)
		}
	}

	dropped := map[string]bool{}
	for _, name := range n.indexes {
		dropped[name] = true
	}
	indexes, err := u.sqliteIndexes(n.table, nil)
	if err != nil {
		return err
	}
	var restore []string
	for _, stmt := range indexes {
		m := createsIndex.FindStringSubmatch(stmt)
		if m == nil || dropped[m[1]] || mentionsAny(stmt, gone) {
			continue
		}
		restore = append(restore, stmt)
	}

	staging := n.table + "_downgrading"
	stmts := []string{
		`CREATE TABLE "` + staging + `" (` + strings.Join(orderConstraintsLast(items), ", ") + `)`,
		`INSERT INTO "` + staging + `" (` + strings.Join(kept, ", ") + `) SELECT ` +
			strings.Join(kept, ", ") + ` FROM "` + n.table + `"`,
		`DROP TABLE "` + n.table + `"`,
		`ALTER TABLE "` + staging + `" RENAME TO "` + n.table + `"`,
	}
	stmts = append(stmts, restore...)
	stmts = append(stmts, n.restore...)
	return u.run(stmts)
}

// orderConstraintsLast keeps a table's constraints after its columns, which
// SQLite requires; the constraints come from a map and are sorted by name so
// the statement is the same on every run.
func orderConstraintsLast(items []string) []string {
	var columns, constraints []string
	for _, item := range items {
		if constraint.MatchString(item) {
			constraints = append(constraints, item)
		} else {
			columns = append(columns, item)
		}
	}
	slices.Sort(constraints)
	return append(columns, constraints...)
}

func mentionsAny(text string, columns map[string]bool) bool {
	for c := range columns {
		if strings.Contains(text, `"`+c+`"`) {
			return true
		}
	}
	return false
}

// returnAdvisories puts each issuance back under the product and issue it was
// issued for, which in v0.1.0 is what an issuance is keyed on. An advisory
// covering several issues is returned under the first of them, and where two
// advisories have the same first issue in the same product, the one issued
// first keeps it: v0.1.0 holds one sequence of issuances per product and
// issue.
func (u *upgrader) returnAdvisories() error {
	type issuance struct {
		ID              int64
		AdvisoryID      int64
		ProductID       int64
		VulnerabilityID int64
		Ordinal         int64
		Digest          string
		Summary         *string
		IssuedBy        int64
		IssuedAt        time.Time
	}
	var rows []issuance
	if err := u.tx.NewRaw(`
		SELECT "ai"."id", "ai"."advisory_id", "first"."product_id", "first"."vulnerability_id", "ai"."ordinal",
			"ai"."digest", "ai"."summary", "ai"."issued_by", "ai"."issued_at"
		FROM "advisory_issuance" AS "ai"
		JOIN "advisory_issue" AS "first" ON "first"."advisory_id" = "ai"."advisory_id"
		WHERE "first"."id" = (SELECT MIN("i"."id") FROM "advisory_issue" AS "i"
			WHERE "i"."advisory_id" = "ai"."advisory_id")
		ORDER BY "ai"."id"`).Scan(u.ctx, &rows); err != nil {
		return fmt.Errorf("read what was issued: %w", err)
	}
	if err := dropTables(u.ctx, u.raw, "advisory_approval", "advisory_issuance",
		"advisory_edition", "advisory_issue", "advisory"); err != nil {
		return err
	}
	if err := upIssuance(u.ctx, u.raw); err != nil {
		return err
	}
	owner := map[[2]int64]int64{}
	for _, r := range rows {
		key := [2]int64{r.ProductID, r.VulnerabilityID}
		if first, taken := owner[key]; taken && first != r.AdvisoryID {
			continue
		}
		owner[key] = r.AdvisoryID
		if _, err := u.tx.ExecContext(u.ctx, `
			INSERT INTO "advisory_issuance" ("id", "product_id", "vulnerability_id", "ordinal",
				"digest", "summary", "issued_by", "issued_at") VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			r.ID, r.ProductID, r.VulnerabilityID, r.Ordinal, r.Digest, r.Summary, r.IssuedBy, r.IssuedAt); err != nil {
			return fmt.Errorf("return issuance %d: %w", r.ID, err)
		}
	}
	return u.continueIdentity("advisory_issuance")
}

// returnDisclosures puts every extension back in v0.1.0's table. A shortening
// has no place there.
func (u *upgrader) returnDisclosures() error {
	if err := upDisclosureExtension(u.ctx, u.raw); err != nil {
		return err
	}
	if _, err := u.tx.ExecContext(u.ctx, `
		INSERT INTO "disclosure_extension" ("id", "vulnerability_id", "product_id",
			"was", "until", "reason", "asked_by", "asked_at", "needs_approval", "approved_by", "approved_at")
		SELECT "id", "vulnerability_id", "product_id",
			"was", "until", "reason", "asked_by", "asked_at", "needs_approval", "approved_by", "approved_at"
		FROM "disclosure_movement" WHERE "act" = ?`, "extension"); err != nil {
		return fmt.Errorf("return the embargo extensions: %w", err)
	}
	if err := u.continueIdentity("disclosure_extension"); err != nil {
		return err
	}
	return dropTables(u.ctx, u.raw, "disclosure_movement")
}
