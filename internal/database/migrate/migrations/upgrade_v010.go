// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	migrate.AddUpgrade(migrate.Upgrade{
		Release: "v0.1.0",
		Applied: []int64{1, 2, 3, 4, 5, 7, 9, 10, 11, 12, 16, 18, 19, 20, 21, 22, 23,
			24, 25, 26, 27, 28, 29, 30, 31, 33, 34, 35, 36},
		Run: upgradeV010,
	})
}

// upgradeV010 changes the schema the v0.1.0 release built into this build's,
// and moves the rows it holds.
//
// Every table and index it creates is created by the statement the migration
// that makes it on a fresh install runs, read from that migration. A column it
// adds is declared as that statement declares it. What is written here is only
// the order, the rows, and the engine differences in how an existing table is
// changed.
func upgradeV010(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}

	steps := []func() error{
		// Tables nothing in v0.1.0 had, whose every reference is to a table it
		// did.
		func() error { return u.create(findingStatements(t), "vulnerability_rating") },
		func() error { return u.create(reportStatements(t), "report_ruling") },
		func() error { return u.create(disclosureMovementStatements(t), "disclosure_movement") },
		func() error {
			return u.create(advisoryStatements(t),
				"advisory", "advisory_edition", "advisory_approval", "advisory_issue")
		},
		func() error { return u.run(vexIssuanceStatements(t)) },
		func() error { return u.run(exploitedHereStatements(t)) },
		func() error { return u.run(advisorySourceStatements(t)) },
		func() error { return u.run(patchBranchStatements(t)) },

		// Columns that take a null, which every existing row holds.
		func() error {
			return u.change(catalogStatements(t), change{table: "product",
				add: []added{{column: "pair_share"}, {column: "pair_approvers"}, {column: "retired_at"}}})
		},
		func() error {
			return u.change(catalogStatements(t), change{table: "stream", add: []added{{column: "retired_at"}}})
		},
		func() error {
			return u.change(catalogStatements(t), change{table: "variant", add: []added{{column: "retired_at"}}})
		},
		func() error {
			return u.change(scanStatements(t), change{table: "scan", add: []added{{column: "root_identifier"}}})
		},

		// Columns every existing row holds one value in.
		func() error {
			return u.change(findingStatements(t), change{table: "vulnerability_weakness",
				add: []added{{column: "is_primary", fill: "FALSE"}}, then: u.primaryWeakness})
		},
		func() error {
			return u.change(findingStatements(t), change{table: "finding",
				add:     []added{{column: "urgency_exploited_here", fill: "FALSE"}},
				indexes: []string{"finding_group_idx"}})
		},
		func() error {
			return u.change(notificationStatements(t), change{table: "notification",
				add: []added{{column: "together", fill: "''"}}})
		},
		func() error {
			return u.change(vexStatements(t), change{table: "vex_statement",
				add: []added{
					{column: "source", fill: "'vex'"},
					{column: "document_id", fill: "''"},
					{column: "about", fill: "''"},
				},
				then:    u.vexAbout,
				indexes: []string{"vex_statement_from_idx"}})
		},
		func() error {
			return u.change(reportStatements(t), change{table: "flaw_report",
				add: []added{
					{column: "reference", fill: `'-' || "id"`, serverFill: "''"},
					{column: "summary"},
					{column: "evaluated_at"},
					{column: "evaluated_by"},
					{column: "ruling_id"},
				},
				relax: []string{"vulnerability_id"},
				then:  u.mintReferences,
				constraints: []string{"flaw_report_reference_unique", "flaw_report_answered_by_fk",
					"flaw_report_judged_by_fk", "flaw_report_ruling_fk"},
				indexes: []string{"flaw_report_product_idx", "flaw_report_ruling_idx"}})
		},
		func() error { return u.create(reportStatements(t), "report_ruled") },
		func() error {
			return u.change(attachmentStatements(t), change{table: "attachment",
				add:         []added{{column: "flaw_report_id"}},
				relax:       []string{"vulnerability_id"},
				constraints: []string{"attachment_report_fk"},
				indexes:     []string{"attachment_report_idx"}})
		},

		// Rows that move to a table of another shape.
		u.moveDisclosures,
		u.moveAdvisories,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

type upgrader struct {
	ctx    context.Context
	tx     bun.Tx
	raw    *sql.Tx
	t      *columnTypes
	engine database.Engine
}

// run applies statements as a migration does.
func (u *upgrader) run(statements []string) error {
	return apply(u.ctx, u.raw, statements)
}

// create applies the statements that make the named tables and their indexes.
func (u *upgrader) create(statements []string, tables ...string) error {
	var picked []string
	for _, table := range tables {
		made, indexes, err := pick(statements, table)
		if err != nil {
			return err
		}
		picked = append(picked, made)
		picked = append(picked, indexes...)
	}
	return u.run(picked)
}

// change describes what one existing table gains.
type change struct {
	table string
	// add is the columns it gains, declared as the fresh install declares
	// them.
	add []added
	// relax is the columns that stop refusing a null.
	relax []string
	// then runs once every column is in place and before any constraint is.
	then func() error
	// constraints and indexes are named as the fresh install names them. An
	// index of that name the table already has is replaced.
	constraints []string
	indexes     []string
}

// addsOnly is a change SQLite can make where the table stands: columns that
// take a null and hold one, and nothing else.
func (c change) addsOnly() bool {
	for _, a := range c.add {
		if a.fill != "" {
			return false
		}
	}
	return len(c.relax) == 0 && len(c.constraints) == 0 && len(c.indexes) == 0 && c.then == nil
}

// added is one column, and the value existing rows take in it. No fill is a
// null.
type added struct {
	column string
	fill   string
	// serverFill replaces fill on the engines that alter a table in place,
	// where a column is filled before its constraints exist. A table rebuilt
	// on SQLite is created with them, so a fill that has to be unique before
	// the value it stands in for is written differs between the two.
	serverFill string
}

// change alters one table into the shape the fresh install gives it.
//
// SQLite cannot drop a default or change whether a column takes a null, so
// there the table is rebuilt from the fresh install's statement and its rows
// copied across. The other three alter it where it stands.
func (u *upgrader) change(statements []string, c change) error {
	made, indexes, err := pick(statements, c.table)
	if err != nil {
		return err
	}
	if u.engine == database.SQLite && !c.addsOnly() {
		return u.rebuild(made, indexes, c)
	}

	items, err := declared(made)
	if err != nil {
		return err
	}
	var stmts []string
	for _, a := range c.add {
		def, err := items.column(a.column)
		if err != nil {
			return err
		}
		fill := a.fill
		if a.serverFill != "" {
			fill = a.serverFill
		}
		if fill == "" {
			stmts = append(stmts, `ALTER TABLE "`+c.table+`" ADD COLUMN `+def)
			continue
		}
		// Added with a default so that every row takes the value at once, and
		// the default dropped so the column is declared as a fresh install
		// declares it.
		stmts = append(stmts,
			`ALTER TABLE "`+c.table+`" ADD COLUMN `+def+` DEFAULT `+fill,
			`ALTER TABLE "`+c.table+`" ALTER COLUMN "`+a.column+`" DROP DEFAULT`)
	}
	for _, column := range c.relax {
		def, err := items.column(column)
		if err != nil {
			return err
		}
		switch u.engine {
		case database.Postgres:
			stmts = append(stmts, `ALTER TABLE "`+c.table+`" ALTER COLUMN "`+column+`" DROP NOT NULL`)
		default:
			stmts = append(stmts, `ALTER TABLE "`+c.table+`" MODIFY COLUMN `+def)
		}
	}
	if err := u.run(stmts); err != nil {
		return err
	}
	if c.then != nil {
		if err := c.then(); err != nil {
			return err
		}
	}

	stmts = nil
	for _, name := range c.constraints {
		def, err := items.constraint(name)
		if err != nil {
			return err
		}
		stmts = append(stmts, `ALTER TABLE "`+c.table+`" ADD `+def)
	}
	for _, name := range c.indexes {
		stmt, err := indexNamed(indexes, name)
		if err != nil {
			return err
		}
		if replaced, err := u.hasIndex(c.table, name); err != nil {
			return err
		} else if replaced {
			if err := dropIndex(u.ctx, u.raw, c.table, name); err != nil {
				return err
			}
		}
		stmts = append(stmts, stmt)
	}
	return u.run(stmts)
}

// rebuild replaces a SQLite table with one made by the fresh install's
// statement, the rows copied across by column name.
//
// Foreign keys are off while this runs, which the upgrade's caller arranges:
// dropping a table other tables point at is otherwise refused. Rows keep their
// identifiers, so every reference into the table still lands.
func (u *upgrader) rebuild(made string, indexes []string, c change) error {
	items, err := declared(made)
	if err != nil {
		return err
	}
	had, err := u.sqliteColumns(c.table)
	if err != nil {
		return err
	}
	fills := map[string]string{}
	for _, a := range c.add {
		fills[a.column] = a.fill
	}

	kept, err := u.sqliteIndexes(c.table, indexes)
	if err != nil {
		return err
	}

	staging := c.table + "_upgrading"
	var into, from []string
	for _, column := range items.columns {
		into = append(into, `"`+column+`"`)
		switch fill, ok := fills[column]; {
		case had[column]:
			from = append(from, `"`+column+`"`)
		case ok && fill != "":
			from = append(from, fill)
		default:
			from = append(from, "NULL")
		}
	}

	stmts := []string{
		createsTable.ReplaceAllString(made, `CREATE TABLE "`+staging+`"`),
		`INSERT INTO "` + staging + `" (` + strings.Join(into, ", ") + `) SELECT ` +
			strings.Join(from, ", ") + ` FROM "` + c.table + `"`,
		`DROP TABLE "` + c.table + `"`,
		`ALTER TABLE "` + staging + `" RENAME TO "` + c.table + `"`,
	}
	stmts = append(stmts, indexes...)
	stmts = append(stmts, kept...)
	if err := u.run(stmts); err != nil {
		return err
	}
	if c.then != nil {
		return c.then()
	}
	return nil
}

func (u *upgrader) sqliteColumns(table string) (map[string]bool, error) {
	rows, err := u.raw.QueryContext(u.ctx, `SELECT "name" FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, fmt.Errorf("read the columns of %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("read the columns of %s: %w", table, err)
		}
		out[name] = true
	}
	return out, rows.Err()
}

// sqliteIndexes is the statements creating a table's indexes that the
// migration declaring the table does not declare. Later migrations add
// indexes to tables an earlier one made, and dropping the table drops them.
func (u *upgrader) sqliteIndexes(table string, declared []string) ([]string, error) {
	named := map[string]bool{}
	for _, stmt := range declared {
		if m := createsIndex.FindStringSubmatch(stmt); m != nil {
			named[m[1]] = true
		}
	}
	rows, err := u.raw.QueryContext(u.ctx, `SELECT "name", "sql" FROM "sqlite_master"
		WHERE "type" = 'index' AND "tbl_name" = ? AND "sql" IS NOT NULL`, table)
	if err != nil {
		return nil, fmt.Errorf("read the indexes of %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name, stmt string
		if err := rows.Scan(&name, &stmt); err != nil {
			return nil, fmt.Errorf("read the indexes of %s: %w", table, err)
		}
		if !named[name] {
			out = append(out, stmt)
		}
	}
	return out, rows.Err()
}

// hasIndex reports whether a table already holds an index of this name, on
// the three engines a table is altered in place on.
func (u *upgrader) hasIndex(table, name string) (bool, error) {
	var query string
	switch u.engine {
	case database.Postgres:
		query = `SELECT 1 FROM "pg_catalog"."pg_indexes"
			WHERE "schemaname" = CURRENT_SCHEMA() AND "tablename" = ? AND "indexname" = ?`
	default:
		query = `SELECT 1 FROM "information_schema"."STATISTICS"
			WHERE "TABLE_SCHEMA" = DATABASE() AND "TABLE_NAME" = ? AND "INDEX_NAME" = ? LIMIT 1`
	}
	var probe int
	err := u.tx.QueryRowContext(u.ctx, query, table, name).Scan(&probe)
	if database.IsNoRows(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("ask whether %s has index %s: %w", table, name, err)
	}
	return true, nil
}

// primaryWeakness marks which weakness an advisory states for a flaw somebody
// recorded here. The person recording one names theirs first, and v0.1.0
// wrote a flaw's weaknesses in the order they were named, in one statement.
//
// An issue a scanner reported is left with none marked. The feed names its
// primary weakness the next time a scan reports the issue.
func (u *upgrader) primaryWeakness() error {
	_, err := u.tx.ExecContext(u.ctx, `
		UPDATE "vulnerability_weakness" SET "is_primary" = ?
		WHERE "id" IN (
			SELECT "first"."id" FROM (
				SELECT MIN("vw"."id") AS "id" FROM "vulnerability_weakness" AS "vw"
				WHERE EXISTS (
					SELECT 1 FROM "finding" AS "f"
					WHERE "f"."vulnerability_id" = "vw"."vulnerability_id" AND "f"."kind" = ?)
				GROUP BY "vw"."vulnerability_id"
			) AS "first"
		)`, true, "entered")
	if err != nil {
		return fmt.Errorf("mark the weakness a recorded flaw names first: %w", err)
	}
	return nil
}

// vexAbout records which version each statement was made about, read from
// the package identifier the way a statement uploaded today is. A statement
// whose identifier names no version is about any version, which is what an
// empty value says.
func (u *upgrader) vexAbout() error {
	type row struct {
		ID   int64
		Purl string
	}
	var rows []row
	if err := u.tx.NewRaw(`SELECT "id", "purl" FROM "vex_statement" WHERE "purl" IS NOT NULL`).
		Scan(u.ctx, &rows); err != nil {
		return fmt.Errorf("read the statements' package identifiers: %w", err)
	}
	for _, r := range rows {
		version := purlVersion(r.Purl)
		if version == "" {
			continue
		}
		if _, err := u.tx.ExecContext(u.ctx,
			`UPDATE "vex_statement" SET "about" = ? WHERE "id" = ?`,
			bound.HeadRunes(version, database.NameWidth), r.ID); err != nil {
			return fmt.Errorf("record which version statement %d is about: %w", r.ID, err)
		}
	}
	return nil
}

// purlVersion is the version a package identifier names, read as the graph
// reads one. Written out here because the graph package reaches, through
// packages whose tests build a schema, back to this one.
func purlVersion(purl string) string {
	purl, _, _ = strings.Cut(strings.TrimSpace(purl), "#")
	body, _, _ := strings.Cut(purl, "?")
	scheme, rest, found := strings.Cut(body, ":")
	if !found || !strings.EqualFold(scheme, "pkg") {
		return ""
	}
	path, version := rest, ""
	if at := strings.LastIndex(rest, "@"); at > 0 {
		path, version = rest[:at], rest[at+1:]
	}
	if len(strings.Split(strings.Trim(path, "/"), "/")) < 2 {
		return ""
	}
	if unescaped, err := url.PathUnescape(version); err == nil {
		return unescaped
	}
	return version
}

// mintReferences gives every report the name it is reached by, in the form a
// report recorded today is given one: the product's name, the year it was
// recorded, and six random digits.
func (u *upgrader) mintReferences() error {
	type row struct {
		ID         int64
		Product    string
		RecordedAt time.Time
	}
	var rows []row
	if err := u.tx.NewRaw(`
		SELECT "fr"."id", "p"."name" AS "product", "fr"."recorded_at"
		FROM "flaw_report" AS "fr" JOIN "product" AS "p" ON "p"."id" = "fr"."product_id"
		ORDER BY "fr"."id"`).Scan(u.ctx, &rows); err != nil {
		return fmt.Errorf("read the reports to name: %w", err)
	}
	taken := map[string]bool{}
	for _, r := range rows {
		prefix := strings.ToUpper(strings.TrimSpace(r.Product))
		var reference string
		for {
			n, err := rand.Int(rand.Reader, big.NewInt(900_000))
			if err != nil {
				return fmt.Errorf("draw a report reference: %w", err)
			}
			reference = fmt.Sprintf("%s-R-%d-%d", prefix, r.RecordedAt.UTC().Year(), 100_000+n.Int64())
			if !taken[reference] {
				break
			}
		}
		taken[reference] = true
		if _, err := u.tx.ExecContext(u.ctx,
			`UPDATE "flaw_report" SET "reference" = ? WHERE "id" = ?`, reference, r.ID); err != nil {
			return fmt.Errorf("name report %d: %w", r.ID, err)
		}
	}
	return nil
}

// moveDisclosures carries every embargo extension into the table that records
// both directions an embargo can move. v0.1.0 refused a move that was not
// later, so every row it holds is an extension.
func (u *upgrader) moveDisclosures() error {
	if _, err := u.tx.ExecContext(u.ctx, `
		INSERT INTO "disclosure_movement" ("id", "vulnerability_id", "product_id", "act",
			"was", "until", "reason", "asked_by", "asked_at", "needs_approval", "approved_by", "approved_at")
		SELECT "id", "vulnerability_id", "product_id", ?,
			"was", "until", "reason", "asked_by", "asked_at", "needs_approval", "approved_by", "approved_at"
		FROM "disclosure_extension"`, "extension"); err != nil {
		return fmt.Errorf("carry the embargo extensions across: %w", err)
	}
	if err := u.continueIdentity("disclosure_movement"); err != nil {
		return err
	}
	return u.run([]string{`DROP TABLE "disclosure_extension"`})
}

// v010Issuance is one row of what v0.1.0 recorded as issued.
type v010Issuance struct {
	ID              int64
	ProductID       int64
	VulnerabilityID int64
	Identifier      string
	Ordinal         int64
	Digest          string
	Summary         *string
	IssuedBy        int64
	IssuedAt        time.Time
}

// heldDocument stands in for a document v0.1.0 issued and did not keep.
//
// The column holds what went out, and nothing can work that out again. An
// empty object parses, and states no distribution a published directory may
// serve, so the directory passes over it until the advisory is issued again.
const heldDocument = "{}"

// moveAdvisories turns each issue v0.1.0 issued an advisory for into an
// advisory covering that one issue, with its issuances beneath it.
//
// An advisory that has been issued keeps the name it was issued under, which
// in v0.1.0 was the issue's own identifier: a revision of a published document
// that changed its tracking identifier would read as a second document. Those
// names were not minted here, so they are numbered in year zero, which no
// advisory minted from the configured prefix is.
func (u *upgrader) moveAdvisories() error {
	var old []v010Issuance
	if err := u.tx.NewRaw(`
		SELECT "ai"."id", "ai"."product_id", "ai"."vulnerability_id", "v"."identifier",
			"ai"."ordinal", "ai"."digest", "ai"."summary", "ai"."issued_by", "ai"."issued_at"
		FROM "advisory_issuance" AS "ai"
		JOIN "vulnerability" AS "v" ON "v"."id" = "ai"."vulnerability_id"
		ORDER BY "ai"."product_id", "ai"."vulnerability_id", "ai"."ordinal"`).Scan(u.ctx, &old); err != nil {
		return fmt.Errorf("read what v0.1.0 issued: %w", err)
	}

	// The fresh install's table replaces v0.1.0's, which has the same name
	// and constraints of the same names; the rows are held in memory across
	// the swap.
	made, indexes, err := pick(advisoryStatements(u.t), "advisory_issuance")
	if err != nil {
		return err
	}
	if err := u.run(append([]string{`DROP TABLE "advisory_issuance"`, made}, indexes...)); err != nil {
		return err
	}

	type key struct{ product, issue int64 }
	advisories := map[key]struct{ advisory, edition int64 }{}
	var number int64
	for _, issued := range old {
		k := key{issued.ProductID, issued.VulnerabilityID}
		ids, seen := advisories[k]
		if !seen {
			number++
			var err error
			ids.advisory, ids.edition, err = u.advisoryFor(issued, number)
			if err != nil {
				return err
			}
			advisories[k] = ids
		}
		if _, err := u.tx.ExecContext(u.ctx, `
			INSERT INTO "advisory_issuance" ("id", "advisory_id", "ordinal", "edition_id",
				"document", "digest", "summary", "issued_by", "issued_at")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			issued.ID, ids.advisory, issued.Ordinal, ids.edition, heldDocument,
			issued.Digest, issued.Summary, issued.IssuedBy, issued.IssuedAt); err != nil {
			return fmt.Errorf("carry issuance %d across: %w", issued.ID, err)
		}
	}
	return u.continueIdentity("advisory_issuance")
}

// v020Advisory and v020Edition are the two rows whose generated identifier
// the upgrade needs back, which the query builder reads the same way on every
// engine.
type v020Advisory struct {
	bun.BaseModel `bun:"table:advisory"`
	ID            int64      `bun:"id,pk,autoincrement"`
	Identifier    string     `bun:"identifier"`
	Folded        string     `bun:"identifier_folded"`
	Year          int64      `bun:"minted_year"`
	Number        int64      `bun:"mint_number"`
	ReleasedFrom  *time.Time `bun:"released_from"`
	MintedAt      time.Time  `bun:"minted_at"`
	MintedBy      int64      `bun:"minted_by"`
}

type v020Edition struct {
	bun.BaseModel `bun:"table:advisory_edition"`
	ID            int64     `bun:"id,pk,autoincrement"`
	AdvisoryID    int64     `bun:"advisory_id"`
	Ordinal       int64     `bun:"ordinal"`
	WrittenBy     int64     `bun:"written_by"`
	WrittenAt     time.Time `bun:"written_at"`
}

// advisoryFor writes the advisory, its one edition and its one issue for the
// first issuance of an issue in a product.
func (u *upgrader) advisoryFor(first v010Issuance, number int64) (advisory, edition int64, err error) {
	var released *time.Time
	if err := u.tx.NewRaw(`
		SELECT MIN("f"."opened_at") FROM "finding" AS "f"
		JOIN "target" AS "t" ON "t"."id" = "f"."target_id"
		JOIN "stream" AS "st" ON "st"."id" = "t"."stream_id"
		WHERE "st"."product_id" = ? AND "f"."vulnerability_id" = ? AND "f"."kind" = ?`,
		first.ProductID, first.VulnerabilityID, "entered").Scan(u.ctx, &released); err != nil {
		return 0, 0, fmt.Errorf("read when %s was first recorded: %w", first.Identifier, err)
	}

	row := &v020Advisory{
		Identifier:   bound.HeadRunes(first.Identifier, database.NameWidth),
		Folded:       bound.HeadRunes(strings.ToLower(strings.TrimSpace(first.Identifier)), database.NameWidth),
		Number:       number,
		ReleasedFrom: released,
		MintedAt:     first.IssuedAt,
		MintedBy:     first.IssuedBy,
	}
	if _, err := u.tx.NewInsert().Model(row).Exec(u.ctx); err != nil {
		return 0, 0, fmt.Errorf("record the advisory for %s: %w", first.Identifier, err)
	}
	written := &v020Edition{AdvisoryID: row.ID, Ordinal: 1, WrittenBy: first.IssuedBy, WrittenAt: first.IssuedAt}
	if _, err := u.tx.NewInsert().Model(written).Exec(u.ctx); err != nil {
		return 0, 0, fmt.Errorf("record the edition of %s: %w", first.Identifier, err)
	}
	advisory, edition = row.ID, written.ID
	if _, err := u.tx.ExecContext(u.ctx,
		`UPDATE "advisory" SET "edition_id" = ? WHERE "id" = ?`, edition, advisory); err != nil {
		return 0, 0, fmt.Errorf("point %s at its edition: %w", first.Identifier, err)
	}
	if _, err := u.tx.ExecContext(u.ctx, `
		INSERT INTO "advisory_issue" ("advisory_id", "product_id", "vulnerability_id", "added_at", "added_by")
		VALUES (?, ?, ?, ?, ?)`,
		advisory, first.ProductID, first.VulnerabilityID, first.IssuedAt, first.IssuedBy); err != nil {
		return 0, 0, fmt.Errorf("name %s in its advisory: %w", first.Identifier, err)
	}
	return advisory, edition, nil
}

// continueIdentity moves a table's generated identifier past the rows written
// into it with identifiers of their own. PostgreSQL's identity does not notice
// an explicit value; the other three engines move past it on the insert.
func (u *upgrader) continueIdentity(table string) error {
	if u.engine != database.Postgres {
		return nil
	}
	// The table is one of the two names written in this file, never input.
	if _, err := u.raw.ExecContext(u.ctx, `SELECT setval(pg_get_serial_sequence('"`+table+`"', 'id'), `+ //nolint:gosec // G202: the name is a constant of this file
		`(SELECT MAX("id") FROM "`+table+`"))`); err != nil {
		return fmt.Errorf("continue %s's identifiers past the rows carried across: %w", table, err)
	}
	return nil
}

// pick finds the statement creating a table among a migration's statements,
// and the statements creating its indexes.
func pick(statements []string, table string) (string, []string, error) {
	var made string
	var indexes []string
	for _, stmt := range statements {
		if m := createsTable.FindStringSubmatch(stmt); m != nil && m[1] == table {
			made = stmt
		}
		if m := createsIndex.FindStringSubmatch(stmt); m != nil && m[2] == table {
			indexes = append(indexes, stmt)
		}
	}
	if made == "" {
		return "", nil, fmt.Errorf("no statement creates %s", table)
	}
	return made, indexes, nil
}

func indexNamed(indexes []string, name string) (string, error) {
	for _, stmt := range indexes {
		if m := createsIndex.FindStringSubmatch(stmt); m != nil && m[1] == name {
			return stmt, nil
		}
	}
	return "", fmt.Errorf("no statement creates index %s", name)
}

// declaration is a CREATE TABLE statement read into its columns and
// constraints.
type declaration struct {
	columns     []string
	definitions map[string]string
	constraints map[string]string
}

var (
	lineComment = regexp.MustCompile(`--[^\n]*`)
	leadingName = regexp.MustCompile(`^"([^"]+)"`)
	constraint  = regexp.MustCompile(`^CONSTRAINT\s+"([^"]+)"`)
)

// declared reads a CREATE TABLE statement's body. The statements here quote
// every identifier and nest no parentheses deeper than a column list, which is
// what makes splitting on the commas at depth one enough.
func declared(stmt string) (*declaration, error) {
	body := lineComment.ReplaceAllString(stmt, "")
	open, shut := strings.Index(body, "("), strings.LastIndex(body, ")")
	if open < 0 || shut < open {
		return nil, fmt.Errorf("cannot read the columns of %s", firstLine(stmt))
	}
	body = body[open+1 : shut]

	d := &declaration{definitions: map[string]string{}, constraints: map[string]string{}}
	depth, start := 0, 0
	var items []string
	for i, r := range body {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				items = append(items, body[start:i])
				start = i + 1
			}
		}
	}
	items = append(items, body[start:])
	for _, item := range items {
		item = strings.Join(strings.Fields(item), " ")
		if m := constraint.FindStringSubmatch(item); m != nil {
			d.constraints[m[1]] = item
			continue
		}
		if m := leadingName.FindStringSubmatch(item); m != nil {
			d.columns = append(d.columns, m[1])
			d.definitions[m[1]] = item
		}
	}
	return d, nil
}

func (d *declaration) column(name string) (string, error) {
	if def, ok := d.definitions[name]; ok {
		return def, nil
	}
	return "", fmt.Errorf("no column %s is declared", name)
}

func (d *declaration) constraint(name string) (string, error) {
	if def, ok := d.constraints[name]; ok {
		return def, nil
	}
	return "", fmt.Errorf("no constraint %s is declared", name)
}
