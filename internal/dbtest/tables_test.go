package dbtest

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// The table list is what empties a database between two tests in a package,
// and membership in it is what this says.
//
// A table a migration makes and this list omits is never emptied. On SQLite
// nothing shows, because each test gets its own copy of the migrated template;
// on the three server engines, where a package's tests share one database, its
// rows leak from one test into the next and surface as an order-dependent
// failure somewhere else entirely. A name in the list that no migration makes
// is the mirror case: a DELETE against a table that is not there, which the
// harness swallows.
//
// SQLite alone. The list is one list for all four engines and the migrations
// are one list of statements, so a second engine would answer the same
// question again in a different dialect.
//
// Membership is what this checks; the order stays hand-kept, because
// putting children before the rows they reference means reading the foreign
// keys, and where a position needed that reasoning the comment beside the name
// is the record of it.
func TestTheTableListNamesEveryTableTheSchemaMakes(t *testing.T) {
	Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		made := TablesIn(t, t.Context(), db)
		listed := make(map[string]bool, len(tables))
		for _, name := range tables {
			listed[name] = true
		}

		for _, name := range made {
			// The migration bookkeeping table is the schema's own and holds
			// what version is applied. Emptying it would undo the migration.
			if name == migrationVersionTable {
				continue
			}
			if !listed[name] {
				t.Errorf("%q is made by a migration and is not in the tables list, "+
					"so its rows survive between tests; add it ahead of everything "+
					"it points at", name)
			}
		}
		for _, name := range tables {
			if !slices.Contains(made, name) {
				t.Errorf("%q is in the tables list and no migration makes it, so "+
					"clearing it is a delete against a table that is not there", name)
			}
		}
	})
}

// migrationVersionTable is goose's own bookkeeping, which records what is
// applied and is therefore not a table tests empty.
const migrationVersionTable = "goose_db_version"
