// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
	"github.com/uptrace/bun/dialect/feature"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/schema"
)

// BatchSize is how many rows one statement carries.
//
// Two of the four engines cap how large a single statement may be, the cap is
// server configuration rather than anything a client can discover, and the
// lowest default in circulation is sixteen megabytes. One real image produces
// over three hundred thousand findings in a single run; sent as one statement
// that is tens of megabytes of SQL, which fails on those two and holds the
// whole set in memory on all four.
//
// The number is small enough that a batch stays far inside every default and
// large enough that the round trips do not dominate.
const BatchSize = 500

// InBatches inserts rows a bounded number at a time, and sets each row's
// identifier from what the database assigned.
func InBatches[T any](ctx context.Context, db bun.IDB, rows []T) error {
	return inBatches(ctx, db, rows, true)
}

// InBatchesUnkeyed inserts rows a bounded number at a time, and reads nothing
// back.
//
// For a writer with no use for the identifiers. Reading them back makes the
// statement return a row for every row it writes, carrying the identifier and
// each column left to its default.
//
// On PostgreSQL a batch is sent as one array a column, which the server
// unpacks into rows, wherever every column the rows carry has an array type.
// A list of rows is parsed a value at a time, and an array is parsed whole.
// Measured on PostgreSQL 16 with one processor over a 1 ms, 100 Mbit link,
// writing 291,500 decisions: 66 to 82 µs a row as a list of rows reading the
// identifiers back, 55 µs as a list reading nothing, and 42 to 43 µs as
// arrays.
func InBatchesUnkeyed[T any](ctx context.Context, db bun.IDB, rows []T) error {
	if typ := reflect.TypeFor[T](); db.Dialect().Name() == dialect.PG && typ.Kind() == reflect.Struct {
		table := db.Dialect().Tables().Get(typ)
		if columns := arrayColumns(table); columns != nil {
			return asArrays(ctx, db, table, columns, rows)
		}
	}
	return inBatches(ctx, db, rows, false)
}

// arrayColumn is one column of a row type, written as an array of its values.
type arrayColumn struct {
	field *schema.Field
	// The array type the values are sent as. The server converts each
	// element to the column's own type as it stores it.
	array string
}

// arrayColumns is every column a row type writes, each with the array type
// its values are sent as, or nil where any of them has none.
//
// A column the database numbers is left out, as a list of rows leaves it to
// its default. A column with a default of its own, or one that stores a zero
// value as null, is written as a list of rows, where a value can be left to
// its default one row at a time.
func arrayColumns(table *schema.Table) []arrayColumn {
	columns := make([]arrayColumn, 0, len(table.Fields))
	for _, field := range table.Fields {
		if field.AutoIncrement {
			continue
		}
		if field.SQLDefault != "" || field.NullZero {
			return nil
		}
		array := arrayTypeOf(field.IndirectType)
		if array == "" {
			return nil
		}
		columns = append(columns, arrayColumn{field: field, array: array})
	}
	if len(columns) == 0 {
		return nil
	}
	return columns
}

// arrayTypeOf is the array type a Go type's values are sent as, or empty for
// a type that names how it is stored itself.
func arrayTypeOf(typ reflect.Type) string {
	if typ.Implements(valuerType) || reflect.PointerTo(typ).Implements(valuerType) {
		return ""
	}
	if typ == timeType {
		return "timestamptz[]"
	}
	switch typ.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint8, reflect.Uint16, reflect.Uint32:
		return "bigint[]"
	case reflect.String:
		return "text[]"
	case reflect.Bool:
		return "boolean[]"
	}
	return ""
}

var (
	valuerType = reflect.TypeFor[driver.Valuer]()
	timeType   = reflect.TypeFor[time.Time]()
)

// asArrays inserts rows a bounded number at a time, each batch as one array a
// column unpacked by the server.
func asArrays[T any](ctx context.Context, db bun.IDB, table *schema.Table,
	columns []arrayColumn, rows []T) error {

	names := make([]string, len(columns))
	arrays := make([]string, len(columns))
	for i, column := range columns {
		names[i] = string(column.field.SQLName)
		arrays[i] = "?::" + column.array
	}
	query := "INSERT INTO " + string(table.SQLName) + " (" + strings.Join(names, ", ") +
		") SELECT * FROM unnest(" + strings.Join(arrays, ", ") + ")"
	for start := 0; start < len(rows); start += BatchSize {
		end := min(start+BatchSize, len(rows))
		values := make([]reflect.Value, len(columns))
		for i, column := range columns {
			values[i] = reflect.MakeSlice(reflect.SliceOf(column.field.StructField.Type), 0, end-start)
		}
		for n := start; n < end; n++ {
			strct := reflect.ValueOf(&rows[n]).Elem()
			for i, column := range columns {
				values[i] = reflect.Append(values[i], column.field.Value(strct))
			}
		}
		args := make([]any, len(columns))
		for i := range values {
			args[i] = pgdialect.Array(values[i].Interface())
		}
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("insert rows %d to %d: %w", start, end, err)
		}
	}
	return nil
}

func inBatches[T any](ctx context.Context, db bun.IDB, rows []T, keyed bool) error {
	// Where the statement hands the identifiers back, they are read from it.
	// Where it does not, the insert counts up from the first.
	features := db.Dialect().Features()
	numbered := keyed && !features.Has(feature.InsertReturning) && !features.Has(feature.Output)
	step := int64(0)
	for start := 0; start < len(rows); start += BatchSize {
		end := min(start+BatchSize, len(rows))
		batch := rows[start:end]
		insert := db.NewInsert().Model(&batch)
		if !keyed {
			insert = insert.Returning("")
		}
		res, err := insert.Exec(ctx)
		if err != nil {
			return fmt.Errorf("insert rows %d to %d: %w", start, end, err)
		}
		if !numbered || len(batch) < 2 {
			continue
		}
		if step == 0 {
			if step, err = increment(ctx, db); err != nil {
				return fmt.Errorf("insert rows %d to %d: %w", start, end, err)
			}
		}
		if err := renumber(db, batch, res, step); err != nil {
			return fmt.Errorf("insert rows %d to %d: %w", start, end, err)
		}
	}
	return nil
}

// increment is the step between the identifiers one MySQL statement assigns.
//
// The other three engines hand the identifiers back, and this one reports
// only the first. A server numbering one row in every n leaves n-1 values between
// two rows of one statement: a cluster sets the step to the number of nodes,
// so that two nodes never assign the same value. Read from the session the
// insert ran on, because a session may set its own.
func increment(ctx context.Context, db bun.IDB) (int64, error) {
	var step int64
	if err := db.QueryRowContext(ctx, `SELECT @@SESSION.auto_increment_increment`).Scan(&step); err != nil {
		return 0, fmt.Errorf("read the step between assigned identifiers: %w", err)
	}
	if step < 1 {
		return 0, fmt.Errorf("the server numbers rows in steps of %d", step)
	}
	return step, nil
}

// renumber sets each row's identifier from the first one a MySQL statement
// assigned and the step between them.
//
// The insert has already written an identifier into each row, counting up by
// one from the first. That is right only where the step is one.
func renumber[T any](db bun.IDB, batch []T, res sql.Result, step int64) error {
	if step == 1 {
		return nil
	}
	table := db.Dialect().Tables().Get(reflect.TypeFor[T]())
	if table == nil || len(table.PKs) != 1 || !table.PKs[0].AutoIncrement {
		return nil
	}
	first, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("read the first assigned identifier: %w", err)
	}
	if first == 0 {
		return nil
	}
	pk := table.PKs[0]
	for i := range batch {
		row := reflect.Indirect(reflect.ValueOf(&batch[i]).Elem())
		if err := pk.ScanValue(row, first+int64(i)*step); err != nil {
			return fmt.Errorf("set an assigned identifier: %w", err)
		}
	}
	return nil
}

// InBatchesKeeping inserts rows a bounded number at a time, leaving alone any
// row another writer got to first.
//
// For a table whose rows are facts rather than somebody's state. A
// component identified by its content is the same row whoever writes it, so
// two writers describing the same library at the same version are agreeing
// rather than colliding — and the loser of that race had its whole
// transaction fail. Two replicas reading two scans at once is the shipped
// arrangement, and the first time a portfolio meets a shared dependency both
// of them try to write it; one was told its upload could not be read, for a
// component that is now present.
//
// The caller reads the identifiers back rather than taking them from here.
// A row somebody else wrote has their identifier and not one this statement
// can report, and a row skipped reports nothing at all — so what the rows say
// afterwards is what a read says, which is the only answer that is true for
// both halves of the set.
//
// One of the few places an engine is asked directly, and it lives here for the
// reason every other such answer does. There is no portable spelling: two of
// them want ON CONFLICT DO NOTHING, and the other two an update on a duplicate
// key that sets the key to itself. Not INSERT IGNORE, which on those two also
// turns a value too wide for its column, a dangling reference and a missing
// value into warnings, and stores the row cut to fit or skips it while the
// insert reports success.
func InBatchesKeeping[T any](ctx context.Context, db bun.IDB, rows []T) error {
	var key string
	if db.Dialect().Name().String() != "pg" && db.Dialect().Name().String() != "sqlite" {
		table := db.Dialect().Tables().Get(reflect.TypeFor[T]())
		if len(table.PKs) == 0 {
			return fmt.Errorf("insert %s keeping another writer's rows: it has no key to match on", table.Name)
		}
		key = table.PKs[0].Name
	}
	for start := 0; start < len(rows); start += BatchSize {
		end := min(start+BatchSize, len(rows))
		batch := rows[start:end]
		insert := db.NewInsert().Model(&batch)
		switch db.Dialect().Name().String() {
		case "pg", "sqlite":
			insert = insert.On("CONFLICT DO NOTHING")
		default:
			insert = insert.On("DUPLICATE KEY UPDATE").Set("? = ?", bun.Ident(key), bun.Ident(key))
		}
		if _, err := insert.Exec(ctx); err != nil {
			return fmt.Errorf("insert rows %d to %d: %w", start, end, err)
		}
	}
	return nil
}

// IDsInBatches calls fn with the identifiers a bounded number at a time.
//
// A list of identifiers in a statement has the same ceiling as a list of rows,
// and closing what a scan no longer contains can name as many of them as
// opening did.
func IDsInBatches(ctx context.Context, ids []int64, fn func(context.Context, []int64) error) error {
	for start := 0; start < len(ids); start += BatchSize {
		end := min(start+BatchSize, len(ids))
		if err := fn(ctx, ids[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// InAnyOf is a membership test over a list too long for one statement.
//
// The same ceiling `IDsInBatches` exists for, met on a read rather than a
// write: a condition cannot be issued in pieces, so the list is split and the
// pieces are OR-ed. Every engine takes that, and each `IN` stays within what
// all four accept.
//
// Answers a condition that is never true for an empty list, which is what an
// empty set means — and what `IN ()` is a syntax error for on two of the four.
//
// The column is an Expr rather than a plain string, for the reason Expr exists:
// a placeholder cannot bind a column name, so this one is spliced into
// statement text, and taking it as an ordinary string leaves nothing between
// that splice and a name arriving from a query parameter except that today's
// callers all pass literals (REQ-66).
func InAnyOf(column Expr, ids []int64) (string, []any) {
	if len(ids) == 0 {
		return "1 = 0", nil
	}
	said := make([]string, 0, len(ids)/BatchSize+1)
	args := make([]any, 0, len(ids)/BatchSize+1)
	for start := 0; start < len(ids); start += BatchSize {
		end := min(start+BatchSize, len(ids))
		said = append(said, string(column)+" IN (?)")
		args = append(args, bun.List(ids[start:end]))
	}
	return "(" + strings.Join(said, " OR ") + ")", args
}
