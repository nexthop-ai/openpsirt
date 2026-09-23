// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"math"
	"slices"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Upgrade carries a database built by a released schema to the schema this
// build makes.
//
// Below 1.0 a schema change edits the migration that created the thing, so a
// released database and this build's migrations disagree about what a version
// number means. Running the migrations over it would apply a later number's
// idea of an earlier table. An upgrade recognizes the release by exactly which
// migrations it applied, changes that schema into this build's in one step,
// and then records this build's migrations as applied.
type Upgrade struct {
	// Release is the tag that built the schema, for the log.
	Release string
	// Applied is every migration version a database of that release has
	// applied, and nothing else. A database is upgraded only when its
	// bookkeeping holds exactly this set.
	Applied []int64
	// Run changes that schema into this build's, moving the rows it holds.
	Run func(ctx context.Context, tx bun.Tx) error
}

var upgrades []Upgrade

// AddUpgrade registers an upgrade from a released schema.
func AddUpgrade(u Upgrade) {
	upgrades = append(upgrades, u)
}

// upgradeRelease runs the upgrade whose release built this database, if one
// did. It runs under the migration lock, before the migrations do.
//
// One transaction, with the bookkeeping written last. On PostgreSQL and SQLite
// a failure leaves the release's schema as it was. On MySQL and MariaDB every
// data-definition statement commits as it runs, so a failure leaves part of
// the upgrade applied under the release's bookkeeping, and what recovers it is
// the backup taken before the upgrade.
func upgradeRelease(ctx context.Context, db *database.DB, logger *slog.Logger) error {
	there, err := versionTableExists(ctx, db)
	if err != nil || !there {
		return err
	}
	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return err
	}
	for _, u := range upgrades {
		if !slices.Equal(applied, sorted(u.Applied)) {
			continue
		}
		current, err := registeredVersions()
		if err != nil {
			return err
		}
		logger.Info("upgrading a database built by an earlier release", "release", u.Release)
		restore, err := suspendForeignKeys(ctx, db)
		if err != nil {
			return err
		}
		err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
			if err := u.Run(ctx, tx); err != nil {
				return err
			}
			if err := foreignKeysHold(ctx, db.Server.Engine, tx); err != nil {
				return err
			}
			return recordApplied(ctx, tx, current)
		})
		if restoreErr := restore(); err == nil {
			err = restoreErr
		}
		if err != nil {
			return fmt.Errorf("upgrade from %s: %w", u.Release, err)
		}
		logger.Info("upgraded a database built by an earlier release", "release", u.Release)
		return nil
	}
	return nil
}

// appliedVersions reads which migrations the bookkeeping says are applied.
//
// The table is a log: a rollback adds a row rather than removing one on some
// versions of the library, so the latest row for a version is what decides.
// Version zero is the library's own first row and is no migration.
func appliedVersions(ctx context.Context, db *database.DB) ([]int64, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT "version_id", "is_applied" FROM "`+versionTable+`" ORDER BY "id"`)
	if err != nil {
		return nil, fmt.Errorf("read which migrations are applied: %w", err)
	}
	defer func() { _ = rows.Close() }()
	state := map[int64]bool{}
	for rows.Next() {
		var version int64
		var on bool
		if err := rows.Scan(&version, &on); err != nil {
			return nil, fmt.Errorf("read which migrations are applied: %w", err)
		}
		state[version] = on
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read which migrations are applied: %w", err)
	}
	var applied []int64
	for version, on := range state {
		if on && version != 0 {
			applied = append(applied, version)
		}
	}
	slices.Sort(applied)
	return applied, nil
}

// registeredVersions is every migration this build carries.
func registeredVersions() ([]int64, error) {
	found, err := goose.CollectMigrations(".", 0, math.MaxInt64)
	if err != nil {
		return nil, fmt.Errorf("list this build's migrations: %w", err)
	}
	versions := make([]int64, 0, len(found))
	for _, m := range found {
		versions = append(versions, m.Version)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("this build carries no migrations")
	}
	return versions, nil
}

// recordApplied replaces the release's bookkeeping with this build's, so the
// migrations that follow find nothing left to do.
func recordApplied(ctx context.Context, tx bun.Tx, versions []int64) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM "`+versionTable+`" WHERE "version_id" <> 0`); err != nil {
		return fmt.Errorf("clear the release's bookkeeping: %w", err)
	}
	for _, version := range versions {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO "`+versionTable+`" ("version_id", "is_applied") VALUES (?, ?)`,
			version, true); err != nil {
			return fmt.Errorf("record migration %d as applied: %w", version, err)
		}
	}
	return nil
}

func sorted(versions []int64) []int64 {
	out := slices.Clone(versions)
	slices.Sort(out)
	return out
}

// suspendForeignKeys turns SQLite's foreign-key enforcement off for the
// upgrade and returns what turns it back on.
//
// SQLite changes a table's shape by building a replacement and dropping the
// original, and dropping a table other tables point at is refused while
// enforcement is on. The setting is ignored inside a transaction, so it is
// made before one begins, on the one connection SQLite is held to. The other
// three engines alter a table where it stands and need nothing.
func suspendForeignKeys(ctx context.Context, db *database.DB) (func() error, error) {
	if db.Server.Engine != database.SQLite {
		return func() error { return nil }, nil
	}
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return nil, fmt.Errorf("suspend foreign keys for the upgrade: %w", err)
	}
	return func() error {
		if _, err := db.ExecContext(context.WithoutCancel(ctx), `PRAGMA foreign_keys = ON`); err != nil {
			return fmt.Errorf("restore foreign keys after the upgrade: %w", err)
		}
		return nil
	}, nil
}

// foreignKeysHold checks, before the upgrade commits, every reference that
// was not enforced while it ran.
func foreignKeysHold(ctx context.Context, engine database.Engine, tx bun.Tx) error {
	if engine != database.SQLite {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("check the references the upgrade left: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		var table string
		var row sql.NullInt64
		var parent string
		var fk int64
		if err := rows.Scan(&table, &row, &parent, &fk); err != nil {
			return fmt.Errorf("check the references the upgrade left: %w", err)
		}
		return fmt.Errorf("the upgrade left a row of %s pointing at no row of %s", table, parent)
	}
	return rows.Err()
}
