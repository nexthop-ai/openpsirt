package dbtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// A Seeded template is a migrated database with a package's fixture rows
// already in it, and T is what the seed made: identifiers, a secret shown
// once, whatever a test needs to reach what was seeded.
//
// On SQLite the seed runs once per binary, against the migrated template, and
// every test copies the result — so a fixture of sixty transactions costs a
// file write per test rather than sixty transactions per test, which for the
// API package was half of what a test cost under the race detector. On the
// three servers a package has one database, so the seed runs per test, after
// the database is emptied.
//
// What the seed made on SQLite is one value shared by every test copying the
// template, and those tests run beside each other, so a test reads it and
// does not write to it.
type Seeded[T any] struct {
	fn func(ctx context.Context, db *database.DB) (T, error)

	once  sync.Once
	bytes []byte
	made  T
	err   error
}

// Seed declares a template seeded by fn.
//
// fn runs against a migrated, empty database and has no test to fail, so it
// returns an error rather than calling into testing: on SQLite it runs once,
// before any test, and the test that finds it failed is whichever asked first.
func Seed[T any](fn func(ctx context.Context, db *database.DB) (T, error)) *Seeded[T] {
	return &Seeded[T]{fn: fn}
}

// Each runs fn against the seeded template on every engine, as Each does.
func (s *Seeded[T]) Each(t *testing.T, fn func(t *testing.T, db *database.DB, made T)) {
	t.Helper()
	run(t, s.unbox(fn), nil, beside, s)
}

// Alone is Each for a test that cannot run beside another in its package,
// as Alone is.
func (s *Seeded[T]) Alone(t *testing.T, fn func(t *testing.T, db *database.DB, made T)) {
	t.Helper()
	run(t, s.unbox(fn), nil, alone, s)
}

// Two runs fn against the seeded template on SQLite and PostgreSQL, as Two
// does.
func (s *Seeded[T]) Two(t *testing.T, fn func(t *testing.T, db *database.DB, made T)) {
	t.Helper()
	run(t, s.unbox(fn), map[database.Engine]bool{database.SQLite: true, database.Postgres: true}, beside, s)
}

// unbox adapts a typed test body to the shape run drives, which carries what
// a seed made without knowing its type.
func (s *Seeded[T]) unbox(fn func(t *testing.T, db *database.DB, made T)) body {
	return func(t *testing.T, db *database.DB, made any) {
		t.Helper()
		fn(t, db, made.(T)) //nolint:forcetypeassert // run hands back what sqlite or server returned, which is a T
	}
}

// sqlite is the seeded template's bytes and what the seed made, built on the
// first call and kept.
//
// The seed runs against a copy of the migrated template in a directory of its
// own, and the bytes are read back after the connection is closed: with the
// journal in write-ahead mode, the close is what folds the journal into the
// file, and a file read while it is open is missing whatever the journal
// still holds.
func (s *Seeded[T]) sqlite() ([]byte, any, error) {
	s.once.Do(func() {
		base, err := sqliteTemplate()
		if err != nil {
			s.err = err
			return
		}
		dir, err := os.MkdirTemp("", "openpsirt-dbtest-seed-")
		if err != nil {
			s.err = err
			return
		}
		defer func() { _ = os.RemoveAll(dir) }()
		path := filepath.Join(dir, "template.db")
		if s.err = os.WriteFile(path, base, 0o600); s.err != nil {
			return
		}
		target, err := database.ParseURL("sqlite://" + path + sqliteTestPragmas)
		if err != nil {
			s.err = err
			return
		}
		ctx := context.Background()
		db, err := database.Open(ctx, target)
		if err != nil {
			s.err = fmt.Errorf("open the template: %w", err)
			return
		}
		s.made, s.err = s.fn(ctx, db)
		if closeErr := db.Close(); s.err == nil && closeErr != nil {
			s.err = fmt.Errorf("close the seeded template: %w", closeErr)
		}
		if s.err != nil {
			return
		}
		s.bytes, s.err = os.ReadFile(path) //nolint:gosec // G304: the path is one this function just chose inside its own temporary directory
	})
	return s.bytes, s.made, s.err
}

// server seeds a server database for one test. The caller has emptied it.
func (s *Seeded[T]) server(ctx context.Context, db *database.DB) (any, error) {
	return s.fn(ctx, db)
}
