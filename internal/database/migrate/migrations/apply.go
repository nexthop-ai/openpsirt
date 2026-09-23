// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// This file holds what every migration in this package does *around* its
// statements, and the column spellings they are written against.
//
// The statements themselves stay where they are and are not shared. They are
// the migration — the tables, the columns and the comments explaining why each
// one is shaped as it is — and there is nothing repeated about them. What is
// here is everything else: asking the context which engine this is, refusing
// an engine there are no spellings for, running each statement, naming the one
// that failed, and the two rules about dropping what a migration made.

// types is the column spellings for the engine a migration is running against.
func types(ctx context.Context) (*columnTypes, error) {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return nil, fmt.Errorf("no schema for %s", e)
	}
	return t, nil
}

// apply runs a migration's statements in order, naming the one that failed.
//
// It also makes a re-run resume rather than collide, on the two engines that
// cannot roll one back. Every migration here is registered in the library's
// transactional form and takes a transaction, and on MySQL and MariaDB that
// transaction is decorative: both commit implicitly before and after every
// data-definition statement. A failure at statement N leaves 1 to N-1
// committed, the rollback removes nothing, and no version row is written — so
// the next start runs the same migration from statement 1 and fails on "table
// already exists". Nothing recovers from that on its own, and every
// replacement process fails its startup probe in turn.
//
// So on those two engines each statement is preceded by a question: does the
// thing it creates already exist? If it does, the statement is skipped and the
// skip is logged, and the migration reaches its end and records its version.
// The other two engines have transactional data definition and never see this;
// the check is skipped there rather than being a cost they pay for nothing.
//
// The probe names the exact object the statement names, and a statement
// whose object it cannot identify is run rather than guessed at, failing the
// way it always did.
//
// It cannot tell a half-applied run of this migration from an
// earlier migration that made the same name. On these two engines a duplicate
// name is stepped over and warned about rather than refused, so it is caught
// by the two engines with transactional data definition — and by the warning,
// which is why the skip is logged rather than silent.
//
// MariaDB accepts `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT
// EXISTS`; MySQL accepts only the first. A probe is what the two have in
// common.
func apply(ctx context.Context, tx *sql.Tx, statements []string) error {
	resumable := false
	switch migrate.EngineFrom(ctx) {
	case database.MySQL, database.MariaDB:
		resumable = true
	}

	for _, stmt := range statements {
		if resumable {
			made, err := alreadyMade(ctx, tx, stmt)
			if err != nil {
				return fmt.Errorf("%s: %w", firstLine(stmt), err)
			}
			if made {
				migrate.LoggerFrom(ctx).Warn(
					"a migration is resuming past something it had already created",
					"statement", firstLine(stmt))
				continue
			}
		}
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

// dropTables drops tables in the order given, which is the order a rollback
// needs: a table is dropped before anything it points at.
func dropTables(ctx context.Context, tx *sql.Tx, names ...string) error {
	for _, name := range names {
		// Quoted, like every other identifier in the schema. A reserved word
		// is only reserved when bare, and the four engines do not agree on
		// which words those are — so an unquoted name fails on whichever
		// engine somebody is least likely to be running.
		if _, err := tx.ExecContext(ctx, `DROP TABLE "`+name+`"`); err != nil {
			return fmt.Errorf("drop %s: %w", name, err)
		}
	}
	return nil
}

// dropIndex drops an index, naming its table on the engines that require it.
//
// MySQL and MariaDB spell this `DROP INDEX "n" ON "t"`; the other two take the
// index name alone and refuse the table.
func dropIndex(ctx context.Context, tx *sql.Tx, table, name string) error {
	if _, err := tx.ExecContext(ctx, dropIndexStatement(ctx, table, name)); err != nil {
		return fmt.Errorf("drop index %s: %w", name, err)
	}
	return nil
}

// dropIndexStatement is the branch on its own, so a test can read it without
// an engine to run it against — the engines do not disagree about what the
// statement is, only about which of the two they accept.
func dropIndexStatement(ctx context.Context, table, name string) string {
	stmt := `DROP INDEX "` + name + `"`
	switch migrate.EngineFrom(ctx) {
	case database.MySQL, database.MariaDB:
		stmt += ` ON "` + table + `"`
	}
	return stmt
}

// creates recognizes the two kinds of object these migrations make, and the
// name each statement gives it. Every identifier in the schema is quoted, so
// the quotes are what is matched rather than a bare word.
var (
	createsTable = regexp.MustCompile(`(?is)^\s*CREATE\s+TABLE\s+"([^"]+)"`)
	createsIndex = regexp.MustCompile(`(?is)^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+"([^"]+)"\s+ON\s+"([^"]+)"`)
)

// alreadyMade reports whether the object a statement creates is already there.
//
// Only what this can name for certain. A statement it does not recognize is
// run, which is what every statement did before this existed.
func alreadyMade(ctx context.Context, tx *sql.Tx, stmt string) (bool, error) {
	if m := createsTable.FindStringSubmatch(stmt); m != nil {
		return exists(ctx, tx,
			`SELECT 1 FROM "information_schema"."TABLES"
			 WHERE "TABLE_SCHEMA" = DATABASE() AND "TABLE_NAME" = ?`, m[1])
	}
	if m := createsIndex.FindStringSubmatch(stmt); m != nil {
		return exists(ctx, tx,
			`SELECT 1 FROM "information_schema"."STATISTICS"
			 WHERE "TABLE_SCHEMA" = DATABASE() AND "TABLE_NAME" = ? AND "INDEX_NAME" = ?`,
			m[2], m[1])
	}
	return false, nil
}

func exists(ctx context.Context, tx *sql.Tx, query string, args ...any) (bool, error) {
	var probe int
	err := tx.QueryRowContext(ctx, query, args...).Scan(&probe)
	if database.IsNoRows(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("ask whether this was already created: %w", err)
	}
	return true, nil
}

// columnTypes holds the spellings that differ between engines. Everything the
// application queries is portable; only the declarations are not.
type columnTypes struct {
	id        string // primary key, generated
	ref       string // foreign key column
	refNull   string // nullable foreign key column
	name      string // short identifier, indexed and compared
	free      string // text a producer supplies, of no length we control
	text      string // free text
	date      string // a calendar date
	timestamp string // a moment
	boolean   string
	kind      string
	hash      string // a hex digest
	blob      string // opaque bytes, a bounded slice of a larger document
	suffix    string
}

func typesFor(e database.Engine) *columnTypes {
	switch e {
	case database.Postgres:
		return &columnTypes{
			id: "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY", ref: "BIGINT", refNull: "BIGINT",
			name: "VARCHAR(" + strconv.Itoa(database.NameWidth) + ")", free: "TEXT", text: "TEXT", date: "DATE", timestamp: "TIMESTAMPTZ",
			boolean: "BOOLEAN", kind: "VARCHAR(16)", hash: "VARCHAR(64)", blob: "BYTEA",
		}
	case database.MySQL, database.MariaDB:
		return &columnTypes{
			id: "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY", ref: "BIGINT", refNull: "BIGINT",
			name: "VARCHAR(" + strconv.Itoa(database.NameWidth) + ")", date: "DATE", timestamp: "DATETIME(6)",
			// Sixteen megabytes for text somebody typed. The smaller type
			// holds 65,535 bytes, and the policy that checks typed text
			// before it is stored admits 65,536 — so a field that passed
			// submission failed the write on these two engines and was
			// recorded on the other two, or truncated silently outside
			// strict mode, leaving an approver agreeing to words that are
			// not the words that were written.
			//
			// The producer-supplied slot is the same type, for a stronger
			// reason. Typed text is at least bounded at submission; this is
			// text a producer put in a scan file, of no length anything here
			// controls, and it was the *smaller* of the two — 64 KB against
			// 16 MB, on these two engines only, which is the inversion of
			// what the two slots are declared to mean. No column of this
			// class is indexed or unique, so widening it widens no key: the
			// names that are indexed are the folded ones beside them, which
			// are short and stay short.
			text: "MEDIUMTEXT", free: "MEDIUMTEXT",
			boolean: "TINYINT(1)", kind: "VARCHAR(16)", hash: "VARCHAR(64)",
			// Sixteen megabytes, which is far more than a chunk ever holds.
			// The smaller type tops out at 64 KB, which is not.
			blob: "MEDIUMBLOB",
			// The collation is pinned because these two default to
			// case-insensitive where the other two engines are case-sensitive.
			// Unpinned, declaring "Widget" and then filing a scan against
			// "widget" resolves on one pair and creates a second product on
			// the other — the declaration rule that exists to catch a typo
			// would itself behave differently by engine. Binary comparison is
			// what the other two already do.
			//
			// The row format is pinned for the same kind of reason: it is the
			// default on every server at or above the floor this supports, and
			// a server set back to COMPACT bounds an index key at 767 bytes.
			// One index here is wider than that — what an administrative
			// change is about is three names, and four bytes a character under
			// utf8mb4 — so unpinned, the migration that creates it succeeds on
			// a default server and dies on a configured one with "Specified
			// key was too long". Pinning what is already true everywhere costs
			// nothing and takes a server variable out of whether the schema
			// can be created.
			suffix: " ENGINE=InnoDB ROW_FORMAT=DYNAMIC DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin",
		}
	case database.SQLite:
		// DATETIME, not TEXT: the driver decides how to return a value from
		// the declared type, and TEXT will not scan into a time.Time.
		return &columnTypes{
			id: "INTEGER PRIMARY KEY AUTOINCREMENT", ref: "INTEGER", refNull: "INTEGER",
			name: "TEXT", free: "TEXT", text: "TEXT", date: "DATE", timestamp: "DATETIME",
			boolean: "BOOLEAN", kind: "TEXT", hash: "TEXT", blob: "BLOB",
		}
	}
	return nil
}

// firstLine is what a failed statement is named by. The whole of a CREATE
// TABLE is ninety lines of data definition.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
