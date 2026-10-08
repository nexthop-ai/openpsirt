// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"io"
	"log/slog"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// v050 is the migration that makes v0.5.0's schema, the version a database
// v0.5.0 built records.
const v050 = migrations.Baseline

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
