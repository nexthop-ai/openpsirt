// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// maxSlots is how many test binaries of one package may hold a database on
// one server at once. A run of the whole tree holds one slot per package, so
// this bounds concurrent runs of the same package from different checkouts.
const maxSlots = 32

// harnessPrefix begins the name of every database this harness makes.
const harnessPrefix = "openpsirt_t_"

// slotNamespace keeps the PostgreSQL slot locks apart from every other
// advisory lock on the server. The two-key form of an advisory lock never
// shares a key with the one-key form the migration lock takes.
const slotNamespace int32 = 0x6f707374

// errNoSlot is the refusal when every slot of a package is held.
var errNoSlot = errors.New("every slot is held")

// lease is one slot of one package on one server, held for as long as the
// connection it was taken on is open. A test binary never releases its own:
// the process ending closes the connection, and the server releases the lock
// with it, which is also what happens when the binary crashes.
type lease struct {
	engine database.Engine
	db     *database.DB
	conn   *sql.Conn
	slot   int
	key    string
}

// takeSlot leases the lowest free slot of the package at path on the server
// base names.
//
// Each slot is tried without waiting, so two binaries starting at once each
// come away with a different one: the server grants a lock to one connection
// and refuses the other, which moves on to the next slot.
//
// The lock is keyed on the package as well as the slot. Two packages hold
// different databases, so they can share a slot number, and a key of the slot
// alone would make every package in a run take a slot of its own.
func takeSlot(ctx context.Context, engine database.Engine, base, path string) (*lease, error) {
	target, err := database.ParseURL(base)
	if err != nil {
		return nil, err
	}
	db, err := database.Open(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", target.Redacted, err)
	}
	conn, err := db.DB.DB.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("hold a connection to %s: %w", target.Redacted, err)
	}
	for slot := 1; slot <= maxSlots; slot++ {
		key := slotName(path, slot)
		held, err := tryLock(ctx, conn, engine, key)
		if err != nil {
			_ = conn.Close()
			_ = db.Close()
			return nil, err
		}
		if held {
			return &lease{engine: engine, db: db, conn: conn, slot: slot, key: key}, nil
		}
	}
	_ = conn.Close()
	_ = db.Close()
	return nil, fmt.Errorf("lease a slot for %s on %s: %w, %d of them", path, target.Redacted, errNoSlot, maxSlots)
}

// release gives the slot back and closes the connection that held it.
func (l *lease) release(ctx context.Context) error {
	err := unlock(ctx, l.conn, l.engine, l.key)
	if cerr := l.conn.Close(); err == nil {
		err = cerr
	}
	if cerr := l.db.Close(); err == nil {
		err = cerr
	}
	return err
}

// tryLock takes the lock named key on conn if nobody holds it, without
// waiting, and reports whether it did.
//
// Both locks live with the session: a connection that closes, however it
// closes, releases what it held. On PostgreSQL an advisory lock belongs to the
// database the connection is in, so every lease and every clean connects to
// the database the configured URL names. A MySQL named lock belongs to the
// server.
func tryLock(ctx context.Context, conn *sql.Conn, engine database.Engine, key string) (bool, error) {
	switch engine {
	case database.Postgres:
		var granted bool
		if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1, $2)`,
			slotNamespace, slotHash(key)).Scan(&granted); err != nil {
			return false, fmt.Errorf("ask for the slot lock %s: %w", key, err)
		}
		return granted, nil
	case database.MySQL, database.MariaDB:
		// 1 when granted, 0 when another session holds it, NULL on error.
		var granted sql.NullInt64
		if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK(?, 0)`, key).Scan(&granted); err != nil {
			return false, fmt.Errorf("ask for the slot lock %s: %w", key, err)
		}
		return granted.Valid && granted.Int64 == 1, nil
	default:
		return false, fmt.Errorf("%s has no slot lock", engine)
	}
}

// unlock releases the lock named key, which conn holds.
func unlock(ctx context.Context, conn *sql.Conn, engine database.Engine, key string) error {
	query := `SELECT RELEASE_LOCK(?)`
	args := []any{key}
	if engine == database.Postgres {
		query = `SELECT pg_advisory_unlock($1, $2)`
		args = []any{slotNamespace, slotHash(key)}
	}
	if _, err := conn.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("release the slot lock %s: %w", key, err)
	}
	return nil
}

// slotHash is the PostgreSQL lock key for a slot's name. Two names meeting on
// one hash contend for one lock, which costs one of them the next slot and
// never shares a database.
func slotHash(key string) int32 {
	sum := sha256.Sum256([]byte(key))
	return int32(binary.BigEndian.Uint32(sum[:4])) //nolint:gosec // G115: a hash, whose sign carries nothing
}

// slotName is a slot of the package at path: the package's own name for a
// person reading the server's list, a hash of its import path, and the slot's
// number. It is the name of the slot's lock, and every database the slot holds
// begins with it.
//
// The hash tells apart two packages whose names are cut to the same readable
// part. The checkout is not in it: every checkout shares a package's slots, and
// the lock is what keeps two of them out of one database at once.
func slotName(path string, slot int) string {
	base := strings.TrimSuffix(filepath.Base(path), ".test")
	base = notIdentifier.ReplaceAllString(strings.ToLower(base), "_")
	if len(base) > 24 {
		base = base[:24]
	}
	sum := sha256.Sum256([]byte(path))
	return fmt.Sprintf("%s%s_%s_%02d", harnessPrefix, base, hex.EncodeToString(sum[:3]), slot)
}

// databaseName is the database a slot of the package at path holds for a
// schema built by the migrations that fingerprint identifies. Short enough for
// every engine's limit on identifier length.
func databaseName(path string, slot int, fingerprint string) string {
	schema := sha256.Sum256([]byte(fingerprint))
	return slotName(path, slot) + "_" + hex.EncodeToString(schema[:3])
}

// slotOf is the slot a database belongs to: its name without the schema's
// fingerprint, which is the name of the lock whoever uses it holds.
func slotOf(name string) string {
	return name[:strings.LastIndex(name, "_")]
}

// packagePrefix is everything in a name before the schema's fingerprint: this
// package, in this slot. Every database under it was built for these tests, by
// one set of migrations or another.
func packagePrefix(name string) string {
	return slotOf(name) + "_"
}

var notIdentifier = regexp.MustCompile(`[^a-z0-9_]+`)

// CleanServers drops the harness's databases on every configured server that
// no running test binary holds, and says what it dropped and what it left.
//
// A database is dropped only while this holds its slot's lock, so a binary
// starting meanwhile is refused that slot and takes another. A database whose
// name carries no slot has a lock nobody takes, and is dropped with the rest.
func CleanServers(ctx context.Context, out io.Writer) error {
	var errs []error
	cleaned := 0
	for _, c := range candidates() {
		if c.env == "" {
			continue
		}
		base := os.Getenv(c.env)
		if base == "" {
			_, _ = fmt.Fprintf(out, "%s: %s is not set, so nothing was cleaned there\n", c.name, c.env)
			continue
		}
		cleaned++
		dropped, held, err := dropUnheld(ctx, c.name, base, harnessPrefix)
		_, _ = fmt.Fprintf(out, "%s: dropped %d databases, left %d a running test holds\n",
			c.name, len(dropped), len(held))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.name, err))
		}
	}
	if cleaned == 0 {
		errs = append(errs, errors.New("no server is configured, so nothing was cleaned"))
	}
	return errors.Join(errs...)
}

// dropUnheld drops every database under prefix on the server base names whose
// slot lock nobody holds, and returns the names it dropped and the names it
// left because a lease holds them.
//
// Whether a slot is held is asked by taking its lock without waiting, on a
// connection of this function's own, and the lock is kept across the drop. A
// check followed by a drop would leave a moment in which a test binary leases
// the slot and starts using the database being dropped.
func dropUnheld(ctx context.Context, engine database.Engine, base, prefix string) (dropped, held []string, err error) {
	target, err := database.ParseURL(base)
	if err != nil {
		return nil, nil, err
	}
	admin, err := database.Open(ctx, target)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", target.Redacted, err)
	}
	defer func() { _ = admin.Close() }()
	conn, err := admin.DB.DB.Conn(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("hold a connection to %s: %w", target.Redacted, err)
	}
	defer func() { _ = conn.Close() }()

	names, err := databasesFor(ctx, admin, engine, prefix)
	if err != nil {
		return nil, nil, err
	}
	var errs []error
	for _, name := range names {
		key := slotOf(name)
		free, err := tryLock(ctx, conn, engine, key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !free {
			held = append(held, name)
			continue
		}
		if _, err := conn.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+name+`"`); err != nil {
			errs = append(errs, fmt.Errorf("drop %s: %w", name, err))
		} else {
			dropped = append(dropped, name)
		}
		if err := unlock(ctx, conn, engine, key); err != nil {
			errs = append(errs, err)
		}
	}
	return dropped, held, errors.Join(errs...)
}
