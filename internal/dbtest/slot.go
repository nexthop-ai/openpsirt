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
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// maxSlots is how many test binaries built from one schema may hold a
// database on one server at once: every package of every run on that server,
// from every checkout whose migrations carry the same fingerprint.
const maxSlots = 64

// harnessPrefix begins the name of every database this harness makes.
const harnessPrefix = "openpsirt_t_"

// slotNamespace keeps the PostgreSQL slot locks apart from every other
// advisory lock on the server. The two-key form of an advisory lock never
// shares a key with the one-key form the migration lock takes.
const slotNamespace int32 = 0x6f707374

// errNoSlot is the refusal when every slot of a schema is held.
var errNoSlot = errors.New("every slot is held")

// serverBuilds counts the server databases this process has migrated. A test
// reads it to tell a database used as it stood from one built again.
var serverBuilds atomic.Int64

// lease is one slot of one schema on one server, held for as long as the
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

// leaseDatabase leases a slot of the schema fingerprint identifies, on the
// server base names, and leaves the slot's database migrated to that schema.
// It returns the lease, which the caller keeps for as long as it uses the
// database, and the database's URL.
//
// The slot's database is used as it stands where it already holds the schema
// whole, so a binary following another into a slot migrates nothing. A
// database this lease had to create is the first of its schema in the slot,
// and the databases of other schemas nobody holds are dropped then.
func leaseDatabase(ctx context.Context, engine database.Engine, base, namespace, fingerprint string) (*lease, string, error) {
	held, err := takeSlot(ctx, engine, base, namespace, fingerprint)
	if err != nil {
		return nil, "", err
	}
	own, created, err := prepareServer(ctx, engine, base, held.key)
	if err == nil && created {
		err = dropStale(ctx, engine, base, namespace, held.key)
	}
	if err != nil {
		_ = held.release(ctx)
		return nil, "", err
	}
	return held, own, nil
}

// takeSlot leases the lowest free slot of the schema fingerprint identifies,
// in namespace, on the server base names.
//
// Each slot is tried without waiting, so two binaries starting at once each
// come away with a different one: the server grants a lock to one connection
// and refuses the other, which moves on to the next slot.
//
// The lock is keyed on the schema and the slot, and on nothing about the
// package: a package's binary that exits frees its slot, and its database, to
// the next binary of any package.
func takeSlot(ctx context.Context, engine database.Engine, base, namespace, fingerprint string) (*lease, error) {
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
		key := slotName(namespace, fingerprint, slot)
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
	return nil, fmt.Errorf("lease a slot on %s: %w, %d of them", target.Redacted, errNoSlot, maxSlots)
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

// slotName is a slot of the schema fingerprint identifies: the namespace, a
// hash of the fingerprint and the slot's number. It is the name of the slot's
// lock and of the database the slot holds, and it is short enough for every
// engine's limit on an identifier and MySQL's on a lock name.
//
// Neither the package nor the checkout is in it. Every binary built from one
// schema shares its slots, and the lock is what keeps two of them out of one
// database at once.
func slotName(namespace, fingerprint string, slot int) string {
	sum := sha256.Sum256([]byte(fingerprint))
	return fmt.Sprintf("%s%s_%02d", namespace, hex.EncodeToString(sum[:6]), slot)
}

// slotShape matches a name slotName gives, in namespace, and captures the
// fingerprint's hash.
func slotShape(namespace string) *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(namespace) + `([0-9a-f]{12})_[0-9]{2}$`)
}

// locksOf is every lock whose holder may be using the database called name:
// the lock named for the database, and the one named for it without its last
// part, which is the slot lock of a harness that names a database for its
// package, a slot and a schema.
func locksOf(name string) []string {
	if cut := strings.LastIndex(name, "_"); cut > 0 {
		return []string{name, name[:cut]}
	}
	return []string{name}
}

// dropStale drops the databases in namespace on the server base names that
// were built for another schema and that nobody holds. own is the database
// just created, whose schema's databases are all left.
//
// A database another checkout uses is held, and is left. One it used a moment
// ago is not, and it builds that database again the next time it leases the
// slot.
func dropStale(ctx context.Context, engine database.Engine, base, namespace, own string) error {
	shape := slotShape(namespace)
	mine := shape.FindStringSubmatch(own)
	stale := func(name string) bool {
		match := shape.FindStringSubmatch(name)
		return match != nil && (mine == nil || match[1] != mine[1])
	}
	_, _, err := dropUnheld(ctx, engine, base, namespace, stale)
	return err
}

// CleanServers drops the harness's databases on every configured server that
// no running test binary holds, and says what it dropped and what it left.
//
// A database is dropped only while this holds its slot's lock, so a binary
// starting meanwhile is refused that slot and takes another. A database whose
// name is no slot's has a lock nobody takes, and is dropped with the rest.
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
		dropped, held, err := dropUnheld(ctx, c.name, base, harnessPrefix, nil)
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

// dropUnheld drops every database under prefix on the server base names that
// want accepts, or every one where want is nil, and whose locks nobody holds.
// It returns the names it dropped and the names it left because a lease holds
// them.
//
// Whether a database is held is asked by taking each of its locks without
// waiting, on a connection of this function's own, and the locks are kept
// across the drop. A check followed by a drop would leave a moment in which a
// test binary leases the slot and starts using the database being dropped.
func dropUnheld(ctx context.Context, engine database.Engine, base, prefix string, want func(string) bool) (dropped, held []string, err error) {
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
		if want != nil && !want(name) {
			continue
		}
		taken, free, err := lockAll(ctx, conn, engine, locksOf(name))
		if err != nil {
			errs = append(errs, err)
		}
		if err == nil && !free {
			held = append(held, name)
		}
		if err == nil && free {
			if _, err := conn.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+name+`"`); err != nil {
				errs = append(errs, fmt.Errorf("drop %s: %w", name, err))
			} else {
				dropped = append(dropped, name)
			}
		}
		for _, key := range taken {
			if err := unlock(ctx, conn, engine, key); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return dropped, held, errors.Join(errs...)
}

// lockAll takes every lock in keys on conn without waiting, and stops at the
// first another session holds. It returns the locks it took, which the caller
// releases, and whether it took them all.
func lockAll(ctx context.Context, conn *sql.Conn, engine database.Engine, keys []string) (taken []string, all bool, err error) {
	for _, key := range keys {
		granted, err := tryLock(ctx, conn, engine, key)
		if err != nil {
			return taken, false, err
		}
		if !granted {
			return taken, false, nil
		}
		taken = append(taken, key)
	}
	return taken, true, nil
}
