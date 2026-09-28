// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// A list of identifiers past one statement's ceiling is answered whole.
//
// One row sits in the first batch of identifiers and one in the second, so an
// answer that read only the first batch, or refused the list, is caught.
func TestNamesAreReadForAListPastOneStatement(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		scratchTable(t, db, "named_rows",
			`"id" INTEGER PRIMARY KEY, "name" VARCHAR(16), "label" VARCHAR(16)`)
		late := int64(database.BatchSize + 5)
		if _, err := db.NewRaw(`INSERT INTO "named_rows" ("id", "name", "label")
			VALUES (1, 'first', ''), (?, 'second', 'Second')`, late).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		ids := make([]int64, 0, database.BatchSize+10)
		for id := int64(1); id <= database.BatchSize+10; id++ {
			ids = append(ids, id)
		}

		named, err := database.NamesByID(ctx, db.DB, `"named_rows"`, `"name"`, ids)
		if err != nil {
			t.Fatal(err)
		}
		if len(named) != 2 || named[1] != "first" || named[late] != "second" {
			t.Errorf("read %v, want the two rows there are", named)
		}

		// A composed column, as a display name falling back to another is.
		labeled, err := database.NamesByID(ctx, db.DB, `"named_rows"`,
			database.Composed(`COALESCE(NULLIF("label", ''), "name")`), ids)
		if err != nil {
			t.Fatal(err)
		}
		if labeled[1] != "first" || labeled[late] != "Second" {
			t.Errorf("read %v, want the label where there is one and the name otherwise", labeled)
		}

		none, err := database.NamesByID(ctx, db.DB, `"named_rows"`, `"name"`, nil)
		if err != nil || len(none) != 0 {
			t.Errorf("no identifiers answered %v, %v", none, err)
		}
	})
}
