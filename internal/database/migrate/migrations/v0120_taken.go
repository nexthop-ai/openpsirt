// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"strings"

	"github.com/uptrace/bun"
)

// takenTablesV0120 is each table v0.12.0 gives a value a transaction writes to
// take a row, beside the issue and the build, with v0.11.0's declaration of it.
var takenTablesV0120 = []struct {
	table    string
	declared func(*columnTypes) []string
}{
	{"product", func(t *columnTypes) []string { return declaredV0110(t, "product") }},
	{"branch_or_tag", func(t *columnTypes) []string { return declaredV0110(t, "branch_or_tag") }},
	{"variant", variantV0110},
	{"incident", func(t *columnTypes) []string { return declaredV0110(t, "incident") }},
	{"response_window", func(t *columnTypes) []string { return declaredV0110(t, "response_window") }},
}

// variantV0110 is v0.11.0's declaration of the variant table, which no
// release since the baseline changed.
func variantV0110(t *columnTypes) []string {
	made, indexes, err := pick(catalogBaseline(t), "variant")
	if err != nil {
		panic(err)
	}
	return append([]string{made}, indexes...)
}

// takenV0120 is v0.12.0's declaration of one of takenTablesV0120: v0.11.0's,
// with the value a transaction writes to take a row.
func takenV0120(t *columnTypes, table string) []string {
	for _, each := range takenTablesV0120 {
		if each.table != table {
			continue
		}
		statements := append([]string(nil), each.declared(t)...)
		for i, stmt := range statements {
			if m := createsTable.FindStringSubmatch(stmt); m == nil || m[1] != table {
				continue
			}
			// Before the first constraint, which follows the last column.
			at := strings.Index(stmt, "CONSTRAINT")
			if at < 0 {
				panic("the declaration of " + table + " holds no constraint to place a column before")
			}
			at = strings.LastIndex(stmt[:at], "\n") + 1
			statements[i] = stmt[:at] + `			-- A fresh value written by a transaction taking the row to wait
			-- out another writer of it. It means nothing; a write of a value
			-- already held is skipped on MySQL and MariaDB, and a cluster
			-- never certifies it.
			"taken_by" ` + t.free + ` NULL,
` + stmt[at:]
			return statements
		}
		panic("the declaration of " + table + " creates no such table")
	}
	panic("v0.12.0 gives " + table + " no value to take it with")
}

// takenByV0120 adds the value a transaction takes a row with to each table
// lacking it. Each table is asked alone: a stop between two leaves some added.
func takenByV0120(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, each := range takenTablesV0120 {
		present, err := u.hasColumn(each.table, "taken_by")
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.change(takenV0120(u.t, each.table),
			change{table: each.table, add: []added{{column: "taken_by"}}}); err != nil {
			return err
		}
	}
	return nil
}
