// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// seedSQL is what a seed writes an earlier release's database with: exec runs
// a statement, and id runs one answering a single number. Either fails the
// test it is given, naming the statement.
func seedSQL(ctx context.Context, db *database.DB) (
	exec func(t *testing.T, query string, args ...any), id func(t *testing.T, query string, args ...any) int64) {

	exec = func(t *testing.T, query string, args ...any) {
		t.Helper()
		if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	id = func(t *testing.T, query string, args ...any) int64 {
		t.Helper()
		var out int64
		if err := db.DB.NewRaw(query, args...).Scan(ctx, &out); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
		return out
	}
	return exec, id
}

// seeding is seedSQL failing one test.
func seeding(t *testing.T, ctx context.Context, db *database.DB) (
	exec func(query string, args ...any), id func(query string, args ...any) int64) {

	each, one := seedSQL(ctx, db)
	exec = func(query string, args ...any) {
		t.Helper()
		each(t, query, args...)
	}
	id = func(query string, args ...any) int64 {
		t.Helper()
		return one(t, query, args...)
	}
	return exec, id
}
