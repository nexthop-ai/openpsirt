package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upSettings, downSettings)
}

// Settings an administrator can change at runtime — thresholds, precedence
// orders, modes. Configuration files hold what an operator sets at deploy time;
// this holds what an administrator sets from inside the application.
//
// The data-definition language is written per engine because it genuinely
// differs. Timestamps are the clearest case: PostgreSQL has no DATETIME, and
// MySQL's TIMESTAMP is a 32-bit value that can acquire an implicit default and
// an on-update clause depending on how the server is configured. Neither is a
// portable spelling of "a moment in time we set ourselves".
func upSettings(ctx context.Context, tx *sql.Tx) error {
	var stmt string
	switch e := migrate.EngineFrom(ctx); e {
	case database.Postgres:
		stmt = `CREATE TABLE "application_setting" (
			"name"       VARCHAR(191) NOT NULL PRIMARY KEY,
			"value"      TEXT         NOT NULL,
			"updated_at" TIMESTAMPTZ  NOT NULL
		)`
	case database.MySQL, database.MariaDB:
		// 191 keeps the key inside the index limit on older servers using a
		// four-byte character set.
		//
		// Binary collation, as every other table here declares. This one was
		// written before the shared table suffix existed and never picked it
		// up, so it was the only table in the schema whose names compared
		// case- and accent-insensitively on two engines of the four — which
		// makes two settings collide there and nowhere else, and makes any
		// join between a setting name and a column declared binary an illegal
		// mix of collations on those two engines alone.
		stmt = `CREATE TABLE "application_setting" (
			"name"       VARCHAR(191) NOT NULL PRIMARY KEY,
			"value"      TEXT         NOT NULL,
			"updated_at" DATETIME(6)  NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`
	case database.SQLite:
		// DATETIME, not TEXT. The driver decides how to hand a value back from
		// the *declared* column type: TEXT yields a string, which will not scan
		// into a time.Time. The same portable Go that works on the three
		// production engines would write successfully here and fail to read.
		stmt = `CREATE TABLE "application_setting" (
			"name"       TEXT     NOT NULL PRIMARY KEY,
			"value"      TEXT     NOT NULL,
			"updated_at" DATETIME NOT NULL
		)`
	default:
		return fmt.Errorf("no schema for %s", e)
	}
	return apply(ctx, tx, []string{stmt})
}

func downSettings(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "application_setting")
}
