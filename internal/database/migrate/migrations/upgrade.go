// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// This file holds what a release's upgrade runs on: one transaction around
// the whole of it, and the statements that change an existing table into the
// shape the release declares. Each release's migration supplies the order,
// the rows and its declarations, and calls these.

// inV020 runs a release's upgrade in one transaction. Migration 42 calls it
// by this name, and a tagged release froze that file.
//
// On PostgreSQL and SQLite a failure leaves the schema as it was. On MySQL and
// MariaDB every data-definition statement commits as it runs, so a failure
// leaves part of it applied and the version unrecorded; a backup taken before
// is what recovers it.
//
// SQLite changes a table's shape by building a replacement and dropping the
// original, which is refused while foreign keys are enforced and a table
// points at it. The setting is ignored inside a transaction, so it is made
// before one begins, and every reference is checked before the transaction
// commits. The setting belongs to a connection, so the setting, the
// transaction and the restore all run on one connection held for the whole
// of it. A pool of one is not enough: the pool closes a connection past its
// lifetime as it comes back, and the transaction then opens on a fresh one
// with foreign keys enforced.
func inV020(ctx context.Context, sqldb *sql.DB, run func(context.Context, bun.Tx) error) (err error) {
	engine := migrate.EngineFrom(ctx)
	db, err := database.Query(sqldb, engine)
	if err != nil {
		return err
	}
	body := func(ctx context.Context, tx bun.Tx) error {
		if err := run(ctx, tx); err != nil {
			return err
		}
		return foreignKeysHold(ctx, engine, tx)
	}
	if engine != database.SQLite {
		return db.RunInTx(ctx, nil, body)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("hold a connection for the upgrade: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("suspend foreign keys: %w", err)
	}
	defer func() {
		if _, restore := conn.ExecContext(context.WithoutCancel(ctx), `PRAGMA foreign_keys = ON`); restore != nil && err == nil {
			err = fmt.Errorf("restore foreign keys: %w", restore)
		}
	}()
	return conn.RunInTx(ctx, nil, body)
}

// foreignKeysHold checks every reference SQLite did not enforce while the
// migration ran.
func foreignKeysHold(ctx context.Context, engine database.Engine, tx bun.Tx) error {
	if engine != database.SQLite {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("check the references the migration kept: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		var table, parent string
		var row sql.NullInt64
		var fk int64
		if err := rows.Scan(&table, &row, &parent, &fk); err != nil {
			return fmt.Errorf("check the references the migration kept: %w", err)
		}
		return fmt.Errorf("a row of %s points at no row of %s", table, parent)
	}
	return rows.Err()
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
	// add is the columns it gains, declared as the release declares
	// them.
	add []added
	// drop is the columns the release no longer declares. Whatever a column
	// held is moved before the change, which removes it.
	drop []string
	// then runs once every column is in place and before any constraint is.
	then func() error
	// constraints is named as the release names them.
	constraints []string
}

// addsOnly is a change SQLite can make where the table stands: columns that
// take a null and hold one, and nothing else.
func (c change) addsOnly() bool {
	for _, a := range c.add {
		if a.fill != "" {
			return false
		}
	}
	return len(c.drop) == 0 && len(c.constraints) == 0 && c.then == nil
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

// change alters one table into the shape the release declares.
//
// SQLite cannot drop a default or change whether a column takes a null, so
// there the table is rebuilt from the release's statement and its rows
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
		// the default dropped so the column is declared as the release
		// declares it.
		stmts = append(stmts,
			`ALTER TABLE "`+c.table+`" ADD COLUMN `+def+` DEFAULT `+fill,
			`ALTER TABLE "`+c.table+`" ALTER COLUMN "`+a.column+`" DROP DEFAULT`)
	}
	for _, column := range c.drop {
		stmts = append(stmts, `ALTER TABLE "`+c.table+`" DROP COLUMN "`+column+`"`)
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
	return u.run(stmts)
}

// index makes the named indexes on a table as the release declares them. An
// index of that name the table already has is replaced. The table is left
// where it stands on every engine, SQLite included: an index is made and
// dropped there like anywhere else, and rebuilding the table would copy every
// row to change none of them.
func (u *upgrader) index(statements []string, table string, names ...string) error {
	_, indexes, err := pick(statements, table)
	if err != nil {
		return err
	}
	for _, name := range names {
		stmt, err := indexNamed(indexes, name)
		if err != nil {
			return err
		}
		if replaced, err := u.hasIndex(table, name); err != nil {
			return err
		} else if replaced {
			if err := dropIndex(u.ctx, u.raw, table, name); err != nil {
				return err
			}
		}
		if err := u.run([]string{stmt}); err != nil {
			return err
		}
	}
	return nil
}

// rebuild replaces a SQLite table with one made by the release's
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

// hasIndex reports whether a table already holds an index of this name.
func (u *upgrader) hasIndex(table, name string) (bool, error) {
	var query string
	switch u.engine {
	case database.SQLite:
		query = `SELECT 1 FROM "sqlite_master"
			WHERE "type" = 'index' AND "tbl_name" = ? AND "name" = ?`
	case database.Postgres:
		query = `SELECT 1 FROM "pg_catalog"."pg_indexes"
			WHERE "schemaname" = CURRENT_SCHEMA() AND "tablename" = ? AND "indexname" = ?`
	default:
		query = mysqlIndexProbe
	}
	return exists(u.ctx, u.tx, fmt.Sprintf("%s has index %s", table, name), query, table, name)
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

// withColumn adds a column to a table's declaration, after the column it
// follows.
func withColumn(statement, after, column string) string {
	at := strings.Index(statement, after)
	if at < 0 {
		panic("the declaration being extended has no column " + after)
	}
	at += len(after)
	return statement[:at] + "\n\t\t\t" + column + statement[at:]
}
