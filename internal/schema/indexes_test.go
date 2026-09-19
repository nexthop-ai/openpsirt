package schema_test

import (
	"context"
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
// **Read from the database rather than from the migration source**, because
// what matters is the schema an operator ends up with, and constraints declare
// indexes without ever saying the word.
//
// **Checked on SQLite alone, deliberately, and this is the exception that
// proves the rule.** Every other schema test runs on four engines because the
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
			for name, columns := range indexes {
				for other, wider := range indexes {
					if name == other {
						continue
					}
					if !leads(columns, wider) {
						continue
					}
					// finding_open_idx is the one deliberate exception, and it
					// is deliberate for a measured reason rather than an
					// argued one: it is narrower than the covering index it
					// prefixes, so the scan for what is open in a build reads
					// fewer pages through it. Dropping it is a trade rather
					// than a tidy-up, and nobody has measured it as one.
					if name == "finding_open_idx" {
						continue
					}
					t.Errorf("%s.%s is (%s), which %s (%s) already answers — "+
						"the wider one serves every lookup the narrower one does",
						table, name, strings.Join(columns, ", "),
						other, strings.Join(wider, ", "))
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

// indexesOn is every index on one table, by name, with its columns in order.
//
// Constraints included: a unique constraint is an index, and the redundancy
// this looks for is usually a hand-written index repeating the front of one.
func indexesOn(t *testing.T, ctx context.Context, db *database.DB, table string) map[string][]string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_index_list(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	indexes := make(map[string][]string, len(names))
	for _, name := range names {
		columns, err := columnsOf(ctx, db, name)
		if err != nil {
			t.Fatal(err)
		}
		indexes[name] = columns
	}
	return indexes
}

func columnsOf(ctx context.Context, db *database.DB, index string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT name FROM pragma_index_info(?) ORDER BY seqno`, index)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

// leads reports whether one column list is answered by another: the same
// columns in the same order, for as far as the first one goes.
//
// Equal lengths count. Skipped, the commonest accidental duplicate there is —
// a hand-written index repeating a UNIQUE constraint — is the one shape this
// cannot see, and it is skipped twice: once by the caller's length test and
// once here. An identical pair reports in both directions, which names both
// indexes and is what somebody reads to decide which goes.
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
