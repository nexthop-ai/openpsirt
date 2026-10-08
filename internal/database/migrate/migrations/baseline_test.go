// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"reflect"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Every table and index a baseline declaration makes is one the baseline
// makes from it. A declaration the baseline never picks reads as part of the
// schema and is not.
func TestEveryBaselineDeclarationIsMade(t *testing.T) {
	type source struct {
		declared func(*columnTypes) []string
		tables   map[string]bool
	}
	sources := map[uintptr]*source{}
	for _, each := range baseline {
		key := reflect.ValueOf(each.declared).Pointer()
		if sources[key] == nil {
			sources[key] = &source{declared: each.declared, tables: map[string]bool{}}
		}
		if sources[key].tables[each.table] {
			t.Errorf("the baseline makes %s twice", each.table)
		}
		sources[key].tables[each.table] = true
	}
	checked := 0
	for _, engine := range []database.Engine{database.Postgres, database.MySQL, database.MariaDB, database.SQLite} {
		for _, s := range sources {
			for _, stmt := range s.declared(typesFor(engine)) {
				table := ""
				if m := createsTable.FindStringSubmatch(stmt); m != nil {
					table = m[1]
				} else if m := createsIndex.FindStringSubmatch(stmt); m != nil {
					table = m[2]
				}
				if table == "" {
					t.Errorf("%s: a baseline declaration holds a statement that makes neither a table nor an index",
						firstLine(stmt))
					continue
				}
				checked++
				if !s.tables[table] {
					t.Errorf("%s on %s: the baseline makes %s from another declaration", firstLine(stmt), engine, table)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no baseline statement was read, so nothing was checked")
	}
}
