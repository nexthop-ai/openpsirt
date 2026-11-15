// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"fmt"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// VersionTable is the migration library's bookkeeping table, which it names
// and this only reads.
const VersionTable = "goose_db_version"

// versionTableExists reports whether the migration bookkeeping table is there.
//
// Asking before reading the version keeps "migrate status" from creating it.
// The library's version query creates the table when it is missing, which
// makes a read-only inspection command perform schema changes — and no schema
// rights while running says the running application may hold read and write
// rights only.
//
// The catalog is asked, rather than the table. Selecting from the table
// answers three questions at once and cannot tell them apart: it is not there,
// this credential may not read it, or the database is unreachable. Read as the
// first, a fully populated database whose credentials omit this one table
// reports "schema version 0" — and the reasonable thing to do about "nothing
// is applied" is to migrate. Running migrations under a credential of their
// own is the documented reason automatic migration can be turned off, so that
// credential is the ordinary arrangement rather than an exotic one.
//
// PostgreSQL is asked through pg_class rather than the information schema,
// because the information schema is filtered by privilege on all three
// servers: a role with no rights on a table does not see the table there, so
// it gives back the same conflation this exists to remove. `pg_class` is
// readable by any role, so on that engine the two are genuinely told apart.
//
// On MySQL and MariaDB they are not. Every catalog those engines offer is
// privilege-filtered and there is no unfiltered one, so a credential that may
// not read the table is indistinguishable from an absent table. What that
// costs is bounded: the next thing to run is the version query or a migration,
// both of which fail with the engine's own permission message rather than
// silently.
func versionTableExists(ctx context.Context, db *database.DB) (bool, error) {
	return tableExists(ctx, db, VersionTable)
}

// tableExists reports whether the catalog holds a table of a given name, by
// the name an unqualified reference to it resolves.
func tableExists(ctx context.Context, db *database.DB, name string) (bool, error) {
	return tableExistsOn(ctx, db, db.Server.Engine, name)
}

// tableExistsOn is tableExists asked through q, which reaches an engine of
// the kind given.
func tableExistsOn(ctx context.Context, q database.RowQuerier, engine database.Engine, name string) (bool, error) {
	query, err := catalogQuery(engine)
	if err != nil {
		return false, err
	}
	var probe int
	switch err := q.QueryRowContext(ctx, query, name).Scan(&probe); {
	case database.IsNoRows(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ask whether this database holds %s: %w", name, err)
	}
	return true, nil
}

// catalogQuery asks one engine whether it holds a table of a given name.
//
// A catalog is engine-specific by nature: three of the four have an
// information schema, SQLite has a table of its own, and PostgreSQL is asked
// somewhere else again for the reason above.
//
// On PostgreSQL the name is resolved through the session's whole search path,
// the way the migration library's own unqualified reference resolves it. A
// runtime role with a schema of its own has that schema as its current one,
// and the table the migrations made sits in a schema further along the path.
// Resolving a name needs only the right to use the schema it is found in, so
// the answer is still not filtered by privilege on the table.
func catalogQuery(engine database.Engine) (string, error) {
	switch engine {
	case database.Postgres:
		return `SELECT 1 FROM "pg_catalog"."pg_class"
			WHERE "oid" = to_regclass(?::text) AND "relkind" = 'r'`, nil
	case database.MySQL, database.MariaDB:
		return `SELECT 1 FROM "information_schema"."TABLES"
			WHERE "TABLE_SCHEMA" = DATABASE() AND "TABLE_NAME" = ?`, nil
	case database.SQLite:
		return `SELECT 1 FROM "sqlite_master" WHERE "type" = 'table' AND "name" = ?`, nil
	}
	return "", fmt.Errorf("no way to read the catalog of %s", engine)
}
