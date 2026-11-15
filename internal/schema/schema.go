// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package schema applies this application's schema to a database.
//
// It exists so that using the migration machinery necessarily registers the
// migrations. Importing the runner directly would compile and run against an
// empty migration set, leaving a database that looks migrated and has no
// tables — a failure with no error message.
package schema

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"

	// Registering every migration is what this import is for, and what this
	// package exists for; importing the runner without it still compiles and
	// runs against an empty migration set.
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
)

// Up brings the database up to the schema this build expects.
//
// A database a later release has upgraded is refused. A database is only ever
// upgraded, so this build has nothing it could do to one, and the way back to
// an earlier release is the backup taken before the upgrade.
func Up(ctx context.Context, db *database.DB, logger *slog.Logger) error {
	if err := NotBeforeTheBaseline(ctx, db); err != nil {
		return err
	}
	if err := NotAhead(ctx, db); err != nil {
		return err
	}
	if err := migrate.Up(ctx, db, logger, Notice); err != nil {
		return err
	}
	// Asked again once the lease is let go: a later release may have
	// migrated while this one waited on it, which leaves this one nothing to
	// apply and a schema it cannot read.
	return NotAhead(ctx, db)
}

// WatchEvery is how often an instance serving a database asks whether
// another instance is changing its schema.
const WatchEvery = time.Second

// AcquireWithin bounds how long one look waits for a connection, and
// LookWithin how long its questions take once it has one. A look that fails
// either bound reads as a change. A pool busy with requests delays a look
// without failing it, and only a pool held for the whole of AcquireWithin
// pauses the instance.
const (
	AcquireWithin = 10 * time.Second
	LookWithin    = 2 * time.Second
)

// Notice is how long an upgrade waits, holding the migration lease to change
// the schema, before its first statement: for every serving instance to see
// it, the rest of a look that asked just before it was written, an interval
// and one whole look; then the thirty seconds the longest write a stopped
// request or pass goes on with is bounded by (recording a patch branch visit,
// cleaning up an attachment), and a second more.
const Notice = LookWithin + WatchEvery + AcquireWithin + LookWithin + 30*time.Second + time.Second

// Standing is what an instance serving a database makes of its schema.
type Standing int

const (
	// Serves is a schema at this build's version that nothing is changing.
	Serves Standing = iota
	// Changes is a schema another instance is changing. An instance of this
	// build serves again once it is Serves.
	Changes
	// Superseded is a schema a later release applied, which this build never
	// serves again.
	Superseded
	// Stranded is a schema at or behind this build's version that an upgrade
	// left with its record standing and no lease held to change it: on MySQL or
	// MariaDB part changed by an upgrade that failed, or committed by a
	// migration whose version was never recorded. Nothing serves it until an
	// upgrade reaches the version the record names or the backup is restored.
	Stranded
	// Behind is a schema older than this build's that nothing is changing,
	// such as a restored backup. A start of this build migrates or refuses
	// it, so a serving instance stops and the platform starts it again.
	Behind
)

// Watcher asks what an instance serving a database makes of its schema.
type Watcher struct {
	observer *migrate.Observer
	expected int64
}

// NewWatcher is a Watcher of db for this build.
func NewWatcher(ctx context.Context, db *database.DB) (*Watcher, error) {
	expected, err := Expected()
	if err != nil {
		return nil, err
	}
	observer, err := migrate.NewObserver(ctx, db)
	if err != nil {
		return nil, err
	}
	return &Watcher{observer: observer, expected: expected}, nil
}

// Look reports the schema's standing, with the version applied and the one
// this build carries, bounded by AcquireWithin and LookWithin. A version
// ahead is Superseded even where asking about a change failed: a later
// release may have reshaped what that asks.
func (w *Watcher) Look(ctx context.Context) (Standing, int64, int64, error) {
	change, applied, err := w.observer.Look(ctx, AcquireWithin, LookWithin)
	standing, err := looked(change, applied, w.expected, err)
	return standing, applied, w.expected, err
}

// looked is the standing a look answered, given what asking failed with.
func looked(change migrate.Change, applied, expected int64, failed error) (Standing, error) {
	if applied > expected {
		return Superseded, nil
	}
	if failed != nil {
		return Serves, failed
	}
	return stands(change, applied, expected), nil
}

// stands is the standing of a schema at applied, for a build carrying
// expected, given what a look found of a change. A version ahead outranks a
// change: a later release mid-upgrade has already left this build behind. A
// change outranks a version behind, which an upgrade passes through.
func stands(change migrate.Change, applied, expected int64) Standing {
	switch {
	case applied > expected:
		return Superseded
	case change == migrate.Held:
		return Changes
	case change == migrate.Recorded:
		return Stranded
	case applied < expected:
		return Behind
	}
	return Serves
}

// NotAhead refuses a database whose schema is newer than this build's.
func NotAhead(ctx context.Context, db *database.DB) error {
	applied, err := Version(ctx, db)
	if err != nil {
		return err
	}
	wanted, err := Expected()
	if err != nil {
		return err
	}
	if applied > wanted {
		return fmt.Errorf("the database is at schema version %d, which a later release applied, and "+
			"this build carries %d: a database is only ever upgraded, so deploy the release that "+
			"upgraded it, or restore the backup taken before that upgrade", applied, wanted)
	}
	return nil
}

// through is the release that upgrades a database v0.7.0 or a later release
// built into one this build upgrades in turn. It is the last release whose
// baseline makes v0.7.0's schema.
const through = "v0.10.2"

// throughBaseline is v0.10.2's baseline migration, the first version v0.10.2
// upgrades.
const throughBaseline = 41

// earlier is the release that upgrades a database v0.5.0 or a later release
// built into one v0.10.2 upgrades. v0.10.2 refuses such a database in its
// turn, because its baseline makes v0.7.0's schema at once.
const earlier = "v0.8.0"

// earlierBaseline is v0.8.0's baseline migration, the first version v0.8.0
// upgrades.
const earlierBaseline = 39

// earliest is the release that upgrades a database a release before v0.5.0
// built into one v0.8.0 upgrades. v0.8.0 refuses such a database, because its
// baseline makes v0.5.0's schema at once.
const earliest = "v0.6.0"

// NotBeforeTheBaseline refuses a database a release before v0.9.0 built.
//
// This build makes v0.9.0's schema in one migration and carries none of the
// ones before it, so it has no way to upgrade an earlier schema.
func NotBeforeTheBaseline(ctx context.Context, db *database.DB) error {
	applied, err := Version(ctx, db)
	if err != nil {
		return err
	}
	if BeforeTheBaseline(applied) {
		return fmt.Errorf("the database is at schema version %d, which a release before v0.9.0 "+
			"built, and this build upgrades a database v0.9.0 or a later release built: take a "+
			"backup, run openpsirt migrate up with %s, and deploy this build", applied, UpgradeWith(applied))
	}
	return nil
}

// UpgradeWith names the releases that bring a database below the baseline to
// one this build upgrades, in the order they run.
func UpgradeWith(applied int64) string {
	switch {
	case applied < earlierBaseline:
		return earliest + ", " + earlier + " and then " + through
	case applied < throughBaseline:
		return earlier + " and then " + through
	}
	return through
}

// BeforeTheBaseline reports whether a schema version is one a release before
// v0.9.0 built. Zero is an empty database, which the baseline makes from
// nothing.
func BeforeTheBaseline(applied int64) bool {
	return applied > 0 && applied < migrations.Baseline
}

// Version reports the schema version currently applied.
func Version(ctx context.Context, db *database.DB) (int64, error) {
	return migrate.Version(ctx, db)
}

// Expected reports the schema version this build was written against.
//
// The other half of Version. A deployment that applies migrations separately
// runs a binary and a schema that move independently, and compares this with
// Version to tell whether they moved together.
func Expected() (int64, error) {
	return migrations.Expected()
}
