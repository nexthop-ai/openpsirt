// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// v070 is the migration that makes v0.7.0's schema, the version a database
// v0.7.0 built records.
const v070 = migrations.Baseline

// records is where each tagged release's record of its migrations is kept,
// from this package's directory.
const records = "../released"

// scratchPrefix names a declared table built beside the real one. Every name
// a declaration makes starts with its table's name, so prefixing those names
// keeps the index and constraint names of the two apart on engines where
// those are unique across a database.
const scratchPrefix = "zz_"

func scratch(table, stmt string) string {
	return strings.ReplaceAll(stmt, `"`+table, `"`+scratchPrefix+table)
}

// linesOf is the lines of a description about one table, with the scratch
// prefix taken out of each so the two read alike.
func linesOf(described []string, table, strip string) []string {
	var out []string
	for _, line := range described {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		about := fields[1]
		if fields[0] == "foreign" && len(fields) > 2 {
			about = fields[2]
		}
		about, _, _ = strings.Cut(about, ".")
		if about != table {
			continue
		}
		if strip != "" {
			line = strings.ReplaceAll(line, strip, "")
		}
		out = append(out, line)
	}
	return out
}

// declarationsAreBuilt builds each declaration under a scratch name and
// compares its description with the table the migrations built, line for line
// in both directions.
//
// The scratch tables are dropped before it returns, and however the
// comparison ends, so what follows reads only what the migrations built.
func declarationsAreBuilt(t *testing.T, ctx context.Context, db *database.DB,
	declared map[string][]string) {
	t.Helper()
	var made []string
	drop := func(ctx context.Context) {
		for _, table := range made {
			if _, err := db.ExecContext(ctx, `DROP TABLE "`+table+`"`); err != nil {
				t.Errorf("drop %s: %v", table, err)
			}
		}
		made = nil
	}
	t.Cleanup(func() { drop(context.WithoutCancel(ctx)) })
	defer drop(ctx)
	for table, statements := range declared {
		made = append(made, scratchPrefix+table)
		for _, stmt := range statements {
			if _, err := db.ExecContext(ctx, scratch(table, stmt)); err != nil {
				t.Fatalf("build %s's declaration under a scratch name: %v\n%s", table, err, stmt)
			}
		}
	}
	described := describe(t, ctx, db)
	compared := 0
	for table := range declared {
		built := linesOf(described, table, "")
		fromDeclaration := linesOf(described, scratchPrefix+table, scratchPrefix)
		if len(built) == 0 || len(fromDeclaration) == 0 {
			t.Errorf("%s described as %d lines built and %d declared, so nothing was compared",
				table, len(built), len(fromDeclaration))
			continue
		}
		compared++
		for _, line := range fromDeclaration {
			if !slices.Contains(built, line) {
				t.Errorf("%s is declared with %q and the migrations do not build it", table, line)
			}
		}
		for _, line := range built {
			if !slices.Contains(fromDeclaration, line) {
				t.Errorf("the migrations build %q on %s and it is not declared", line, table)
			}
		}
	}
	if compared == 0 || compared != len(declared) {
		t.Errorf("compared %d of the %d tables declared", compared, len(declared))
	}
}
