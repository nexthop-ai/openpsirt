// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// TestNoIndexRepeatsThePrefixOfAnother pins that the schema declares no index
// whose columns are a leading prefix of another index on the same table.
//
// A B-tree on (a, b) answers a lookup on `a` exactly as well as one on (a): the
// seek is the same and the only difference is a slightly wider entry. So the
// narrower one is machinery nobody chose — it is maintained on every insert and
// every update to those columns, and it earns nothing.
//
// Read from the database rather than from the migration source, because
// what matters is the schema an operator ends up with, and constraints declare
// indexes without ever saying the word.
//
// Checked on SQLite alone, deliberately, and this is the exception that
// proves the rule. Every other schema test runs on four engines because the
// engines disagree — about reserved words, about types, about what an affected
// row count means. They do not disagree about which columns an index is on:
// the statements are one list, and what differs between engines is spelled in
// the column types. This asks what we wrote, not what an engine did with it,
// and asking three more times would cost three more schema builds to learn the
// same answer. Reading index metadata is also spelled four different ways,
// which would put engine-specific code in a test to check something no engine
// varies.
func TestNoIndexRepeatsThePrefixOfAnother(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		if err := schema.Up(ctx, db, quiet()); err != nil {
			t.Fatalf("migrate up: %v", err)
		}

		tables := dbtest.TablesIn(t, ctx, db)
		read, seen := 0, 0
		for _, table := range tables {
			indexes := indexesOn(t, ctx, db, table)
			if len(indexes) > 0 {
				read++
			}
			seen += len(indexes)
			for name, narrow := range indexes {
				for other, wide := range indexes {
					if name == other || !redundant(narrow, wide) {
						continue
					}
					t.Errorf("%s.%s is (%s), which %s (%s) already answers — "+
						"the wider one serves every lookup the narrower one does",
						table, name, strings.Join(narrow.columns, ", "),
						other, strings.Join(wide.columns, ", "))
				}
			}
		}

		// A sweep that read nothing looks exactly like a sweep that found
		// nothing wrong. The table list has a guard of its own and this did
		// not, so introspection answering nothing ran the double loop zero
		// times and reported the invariant held.
		if read == 0 || seen < len(tables) {
			t.Fatalf("read %d indexes across %d of %d tables, so this checked nothing",
				seen, read, len(tables))
		}
	})
}

// index is one index's columns in order, whether it refuses a duplicate, and
// whether it covers only the rows a condition admits.
type index struct {
	columns []string
	unique  bool
	partial bool
}

// redundant reports whether a wider index answers every lookup a narrower one
// does and leaves nothing it enforces unenforced.
//
// A narrower index that refuses duplicates enforces something a wider one that
// does not cannot, so dropping it loses a rule rather than a cost. A partial
// index holds only some rows, so neither of a pair answers for the other.
func redundant(narrow, wide index) bool {
	if narrow.partial || wide.partial {
		return false
	}
	if narrow.unique && !wide.unique {
		return false
	}
	return leads(narrow.columns, wide.columns)
}

// indexesOn is every index on one table, by name.
//
// Constraints included: a unique constraint is an index, and the redundancy
// this looks for is usually a hand-written index repeating the front of one.
func indexesOn(t *testing.T, ctx context.Context, db *database.DB, table string) map[string]index {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT "name", "unique", "partial" FROM pragma_index_list(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	listed := map[string]index{}
	for rows.Next() {
		var name string
		var unique, partial bool
		if err := rows.Scan(&name, &unique, &partial); err != nil {
			t.Fatal(err)
		}
		listed[name] = index{unique: unique, partial: partial}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	for name, held := range listed {
		columns, err := columnsOf(ctx, db, name)
		if err != nil {
			t.Fatal(err)
		}
		held.columns = columns
		listed[name] = held
	}
	return listed
}

// columnsOf is an index's columns in order. A column that is an expression
// has no name, and is written as one no other index's column can equal.
func columnsOf(ctx context.Context, db *database.DB, index string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT "seqno", "name" FROM pragma_index_info(?) ORDER BY "seqno"`, index)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var columns []string
	for rows.Next() {
		var seqno int
		var name sql.NullString
		if err := rows.Scan(&seqno, &name); err != nil {
			return nil, err
		}
		if !name.Valid {
			name.String = fmt.Sprintf("<expression %d of %s>", seqno, index)
		}
		columns = append(columns, name.String)
	}
	return columns, rows.Err()
}

// A narrower index is reported only where a wider one answers its lookups and
// enforces what it enforces.
func TestAnIndexIsRedundantOnlyWhereNothingItEnforcesIsLost(t *testing.T) {
	ab := []string{"a", "b"}
	for _, c := range []struct {
		what         string
		narrow, wide index
		redundant    bool
	}{
		{"a plain prefix", index{columns: ab[:1]}, index{columns: ab}, true},
		{"a unique prefix of a unique index", index{columns: ab[:1], unique: true}, index{columns: ab, unique: true}, true},
		{"a unique prefix of a plain index", index{columns: ab[:1], unique: true}, index{columns: ab}, false},
		{"a plain index repeating a unique one", index{columns: ab}, index{columns: ab, unique: true}, true},
		{"a partial prefix", index{columns: ab[:1], partial: true}, index{columns: ab}, false},
		{"a prefix of a partial index", index{columns: ab[:1]}, index{columns: ab, partial: true}, false},
		{"another leading column", index{columns: []string{"b"}}, index{columns: ab}, false},
	} {
		if got := redundant(c.narrow, c.wide); got != c.redundant {
			t.Errorf("%s: reported redundant %v, want %v", c.what, got, c.redundant)
		}
	}
}

// An index on an expression is read, and its expression matches no column.
func TestAnIndexOnAnExpressionIsRead(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		for _, stmt := range []string{
			`CREATE TABLE "probe" ("name" TEXT, "kind" TEXT)`,
			`CREATE INDEX "probe_lower_idx" ON "probe" (LOWER("name"), "kind")`,
			`CREATE INDEX "probe_name_idx" ON "probe" ("name")`,
		} {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatal(err)
			}
		}
		indexes := indexesOn(t, ctx, db, "probe")
		lower := indexes["probe_lower_idx"]
		if len(lower.columns) != 2 || lower.columns[1] != "kind" {
			t.Fatalf("the expression index reads as %v", lower.columns)
		}
		if redundant(indexes["probe_name_idx"], lower) {
			t.Error("a column was answered by an expression over it")
		}
	})
}

// leads reports whether one column list is answered by another: the same
// columns in the same order, for as far as the first one goes.
//
// Equal lengths count, so an index repeating a UNIQUE constraint — the
// commonest accidental duplicate there is — is reported, once in each
// direction, which names both indexes and is what somebody reads to decide
// which goes.
func leads(shorter, longer []string) bool {
	if len(shorter) > len(longer) {
		return false
	}
	for i, column := range shorter {
		if longer[i] != column {
			return false
		}
	}
	return true
}
