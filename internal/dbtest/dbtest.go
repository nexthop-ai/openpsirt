// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package dbtest runs a test against every database available to it.
//
// SQLite always runs where a test asks for it, so a test of every engine is
// useful with nothing installed. The production engines run when the
// environment points at them, and are skipped loudly otherwise — a skipped
// engine is reported rather than silently absent, because a portability suite
// that quietly tests one engine is worse than none. A test asking only for
// servers fails where none is configured, since it tested nothing, unless
// OPENPSIRT_TEST_ENGINES leaves the servers out, as make test does.
//
// The schema is built once, not once per test. On SQLite the first test
// binary in a run migrates one file and keeps it in this user's cache
// directory, every other binary reads it, and each test copies it — a copy is
// milliseconds where a migration is most of a second. On the three servers
// each binary leases a slot of the schema and the database the slot holds,
// which is kept between binaries and between runs; see serverDatabase.
// Packages running at once therefore share nothing and can run in parallel;
// tests within a package share the database, and one pool of connections to
// it, and the harness empties it before each of them.
//
// A package whose tests start from the same rows declares them once as a
// Seeded template. On SQLite the seed is applied to the template before the
// first copy, so the rows cost nothing per test; on a server it is applied in
// the first test, and every later test has the rows it wrote written back
// after the database is emptied.
//
// Tests within a package run beside each other when SQLite is the only engine
// in the run, because SQLite is the only engine where each test already holds
// a database of its own. See the note at run.
package dbtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/engines"
)

// URL environment variables for the production engines. Absent means skip.
const (
	PostgresURLEnv = "OPENPSIRT_TEST_POSTGRES_URL"
	MySQLURLEnv    = "OPENPSIRT_TEST_MYSQL_URL"
	MariaDBURLEnv  = "OPENPSIRT_TEST_MARIADB_URL"
	// relaxDurabilityEnv set to 1 lets the harness turn off commit
	// durability on a MySQL or MariaDB server, which is a global setting there.
	relaxDurabilityEnv = "OPENPSIRT_TEST_RELAX_DURABILITY"
)

// EnginesEnv narrows which engines run. The rule and its reasoning live in
// the engines package, which is where a test that cannot import this one
// reaches it from.
const EnginesEnv = engines.Env

type candidate struct {
	name database.Engine
	env  string
}

// urlEnv names the environment variable holding a URL for each engine that
// needs one. SQLite needs none: it is a file this harness makes.
var urlEnv = map[database.Engine]string{
	database.Postgres: PostgresURLEnv,
	database.MySQL:    MySQLURLEnv,
	database.MariaDB:  MariaDBURLEnv,
}

// candidates is every engine a test may reach, SQLite first so that the one
// engine every checkout has is the one a failing run reports first.
//
// Derived from database.Engines rather than listed again, so that an engine
// added there is one this harness runs rather than one it silently omits.
func candidates() []candidate {
	all := []candidate{{name: database.SQLite}}
	for _, engine := range database.Engines() {
		if engine == database.SQLite {
			continue
		}
		all = append(all, candidate{name: engine, env: urlEnv[engine]})
	}
	return all
}

// Each runs fn once against every database available, as a subtest.
//
// The database arrives migrated and empty of the previous test's rows.
// SQLite copies a template that was migrated once per run, and a server
// database is migrated once per binary and emptied before every test, so a
// test needs neither a schema.Up nor a Reset of its own.
//
// This is for a test that pins what a query does: every portability defect
// found so far was a query behaving differently on one engine, so a store
// test earns all four. On SQLite each subtest gets a connection of its own,
// closed afterwards; on a server every test in the binary shares one pool,
// described at serverConnection.
func Each(t *testing.T, fn func(t *testing.T, db *database.DB)) {
	t.Helper()
	run(t, plain(fn), nil, beside, nil)
}

// Alone is Each for a test that cannot run beside another in its package.
//
// The database arrives migrated and empty of the previous test's rows.
// SQLite copies a template that was migrated once per run, and a server
// database is migrated once per binary and emptied before every test, so a
// test needs neither a schema.Up nor a Reset of its own.
//
// A test qualifies where it changes something the whole process shares —
// an environment variable, the working directory — rather than one that is
// merely delicate. Everything else uses Each: the databases are already
// separate, and a test that needs the rest of the package held still usually
// needs a fixture of its own instead.
func Alone(t *testing.T, fn func(t *testing.T, db *database.DB)) {
	t.Helper()
	run(t, plain(fn), nil, alone, nil)
}

// Two runs fn against SQLite and PostgreSQL only.
//
// The database arrives migrated and empty of the previous test's rows.
// SQLite copies a template that was migrated once per run, and a server
// database is migrated once per binary and emptied before every test, so a
// test needs neither a schema.Up nor a Reset of its own.
//
// This is for a test that pins something above the store — routing, which
// role reaches which endpoint, the shape of a response — where the queries
// underneath already have their own tests on all four engines. Running such
// a test four times proves nothing the store tests did not, and the API
// package alone was a quarter of the whole suite's time. The rule for
// choosing: if the test would fail on one engine and pass on
// another only because of SQL, it belongs in Each — and that includes a
// handler test that pins what a query returns, hides, conflicts on or spells.
func Two(t *testing.T, fn func(t *testing.T, db *database.DB)) {
	t.Helper()
	run(t, plain(fn), map[database.Engine]bool{database.SQLite: true, database.Postgres: true}, beside, nil)
}

// Servers runs fn against the three server engines and not SQLite.
//
// For a test that needs two transactions open at once, which SQLite cannot
// give it: this harness holds it to one connection, so a second writer waits
// for a connection the first is holding and the test deadlocks rather than
// racing. A deployment's SQLite pool is wider, and serializes writers all the
// same, because every transaction takes the write lock as it begins.
//
// A narrow exemption, and the only one: everything else that pins what a query
// does belongs in Each, whatever it costs. What qualifies here is a test whose
// subject is two writers colliding — which is also where the defects live that
// SQLite cannot show, because it serializes writers and the three servers do
// not.
func Servers(t *testing.T, fn func(t *testing.T, db *database.DB)) {
	t.Helper()
	servers := map[database.Engine]bool{}
	for _, engine := range database.Engines() {
		if engine != database.SQLite {
			servers[engine] = true
		}
	}
	run(t, plain(fn), servers, beside, nil)
}

// Only runs fn against one engine.
//
// The database arrives migrated and empty of the previous test's rows.
// SQLite copies a template that was migrated once per run, and a server
// database is migrated once per binary and emptied before every test, so a
// test needs neither a schema.Up nor a Reset of its own.
//
// The narrowest of the three, and it needs the narrowest reason: not "the
// other engines are slow" but "the other engines cannot disagree". What
// qualifies is a test that asks what *we* wrote rather than what an engine did
// with it — the shape of the schema we declared, say, where the statements are
// one list and only the column types differ. A test that would fail on one
// engine and pass on another belongs in Each, whatever it costs.
//
// It also earns its keep where reading the answer is spelled four different
// ways, since the alternative is engine-specific code in a test to check
// something no engine varies.
func Only(t *testing.T, engine database.Engine, fn func(t *testing.T, db *database.DB)) {
	t.Helper()
	run(t, plain(fn), map[database.Engine]bool{engine: true}, beside, nil)
}

// company is whether a test may run beside the others in its package.
type company bool

const (
	beside company = true
	alone  company = false
)

// body is what run drives: a test, its database, and what a seed made, which
// is nil where nothing was seeded.
type body = func(t *testing.T, db *database.DB, made any)

// plain adapts a test body that takes no seed.
func plain(fn func(t *testing.T, db *database.DB)) body {
	return func(t *testing.T, db *database.DB, _ any) {
		t.Helper()
		fn(t, db)
	}
}

// skipped, where set, is told of every engine the harness skips and why, so a
// test can hold the harness to reporting what it left out.
var (
	skippedMu sync.Mutex
	skipped   func(test string, engine database.Engine, reason string)
)

// skip leaves an engine out of a test, saying why.
func skip(t *testing.T, engine database.Engine, reason string) {
	t.Helper()
	skippedMu.Lock()
	if skipped != nil {
		skipped(t.Name(), engine, reason)
	}
	skippedMu.Unlock()
	t.Skip(reason)
}

// parallel runs a test beside the others in its package, or says in words why
// it cannot. The testing package panics where a test is made parallel twice —
// two harness calls in one test function — or after it set an environment
// variable, and a panic names neither the harness nor the rule.
func parallel(t *testing.T) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("this test runs beside the others on SQLite and cannot here (%v): "+
				"call the harness once per test function, giving each further call a t.Run "+
				"of its own, and not after t.Setenv — or use dbtest.Alone", r)
		}
	}()
	t.Parallel()
	return nil
}

// seeder is a Seeded template of any type, which is what run needs of one.
type seeder interface {
	// sqlite is the seeded template's bytes and what the seed made, built
	// once per binary.
	sqlite() ([]byte, any, error)
	// server seeds an emptied server database for one test.
	server(ctx context.Context, db *database.DB) (any, error)
	// again brings a server database an earlier test left back to the seed's
	// rows without emptying it, and reports false where it did not.
	again(ctx context.Context, db *database.DB) (any, bool)
}

func run(t *testing.T, fn body, only map[database.Engine]bool, keep company, seed seeder) {
	t.Helper()
	wanted := enginesWanted()
	running := runnable(only, wanted)

	// Tests in a package run beside each other only when SQLite is the whole
	// run. On the three servers a package has one database and its tests empty
	// it between themselves, so two at once would clear each other's rows;
	// SQLite copies the migrated template per test, so each already holds a
	// database nothing else can reach.
	//
	// The engine-scoped part matters because the race detector is engine-scoped
	// too. The detector's cost is in-process work, which is most of what SQLite
	// spends and almost none of what a server engine does — 73.6 s against
	// 10.1 s for the API package on SQLite, 16.9 s against 12.0 s on MariaDB —
	// so it runs on SQLite alone, which is the run this parallelism applies to.
	if keep == beside && len(running) == 1 && running[0].name == database.SQLite {
		if err := parallel(t); err != nil {
			t.Fatal(err)
		}
	}

	for _, c := range candidates() {
		t.Run(string(c.name), func(t *testing.T) {
			if only != nil && !only[c.name] {
				skip(t, c.name, fmt.Sprintf("%s is not asked for by this kind of test", c.name))
			}
			if wanted != nil && !wanted[c.name] {
				skip(t, c.name, fmt.Sprintf("%s is excluded by %s", c.name, EnginesEnv))
			}
			base := ""
			if c.env != "" {
				base = os.Getenv(c.env)
				if base == "" {
					skip(t, c.name, fmt.Sprintf("%s is not set, so %s is untested here", c.env, c.name))
				}
			}
			if c.name == database.SQLite {
				var made any
				template, err := sqliteTemplate()
				if seed != nil {
					template, made, err = seed.sqlite()
				}
				if err != nil {
					t.Fatalf("build the SQLite template: %v", err)
				}
				fn(t, Open(t, sqliteCopy(t, template)), made)
				return
			}
			own, err := serverDatabase(c.name, base)
			if err != nil {
				t.Fatalf("prepare a %s database for this package: %v", c.name, err)
			}
			db, err := serverConnection(c.name, own)
			if err != nil {
				t.Fatalf("connect to the %s database for this package: %v", c.name, err)
			}
			// The package's one database on this server holds whatever the
			// previous test, or the previous run, left: the per-test copy
			// SQLite takes has no counterpart on a server. So it is emptied
			// before every test, and seeded where there is a seed; once a
			// seed's rows are kept, undoing what the previous test changed
			// stands in for both where it can. A measurement empties it to
			// the layout a fresh load leaves, because the plan it times
			// depends on that layout.
			var made any
			undone := false
			if seed != nil {
				made, undone = seed.again(t.Context(), db)
			}
			if !undone {
				empty := clear
				if measuring {
					empty = fresh
				}
				if err := empty(t.Context(), db); err != nil {
					t.Fatalf("empty the %s database for this test: %v", c.name, err)
				}
				if seed != nil {
					if made, err = seed.server(t.Context(), db); err != nil {
						t.Fatalf("seed the %s database: %v", c.name, err)
					}
				}
			}
			fn(t, db, made)
		})
	}
	if len(running) == 0 {
		// An engine asked for by name and excluded by name is a run somebody
		// narrowed on purpose — the race pass is SQLite alone and the engine
		// pass leaves SQLite out — so it skips. Nothing configured at all is
		// still a failure: that is a suite reporting green having tested
		// nothing.
		if wanted != nil {
			t.Skipf("every engine this test runs on is excluded by %s", EnginesEnv)
		}
		t.Fatal("no database was available, so nothing was tested")
	}
}

// runnable is the engines this test will actually reach: what its kind asks
// for, narrowed by the environment, narrowed by what is configured.
func runnable(only, wanted map[database.Engine]bool) []candidate {
	var running []candidate
	for _, c := range candidates() {
		switch {
		case only != nil && !only[c.name]:
		case wanted != nil && !wanted[c.name]:
		case c.env != "" && os.Getenv(c.env) == "":
		default:
			running = append(running, c)
		}
	}
	return running
}

func enginesWanted() map[database.Engine]bool {
	return engines.Selected()
}

// Open connects to url and closes the connection when the test ends.
func Open(t *testing.T, url string) *database.DB {
	t.Helper()
	db, target, err := connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	if db.Server.Engine == database.SQLite {
		// One connection, where a deployment has a pool. A read through the
		// root handle inside a transaction then waits for the connection the
		// transaction holds, and the test hangs on it. That is the one engine
		// on which the rule that a transaction reads only through itself
		// fails loudly; with a pool the read answers from a second connection
		// and nothing reports it. Recorded as the settings applied, so a test
		// narrowing the pool for a while puts back one.
		db.SetMaxOpenConns(1)
		db.Pool.MaxOpen, db.Pool.MaxIdle = 1, 1
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close %s: %v", target.Engine, err)
		}
	})
	return db
}

// sqliteCopy returns the URL of a copy of template, in a directory of the
// test's own. A file rather than :memory:, because every pooled connection to
// an in-memory database gets its own empty database, which makes migrations
// appear to vanish between statements.
func sqliteCopy(t *testing.T, template []byte) string {
	t.Helper()
	path := filepath.Join(sqliteDir(t), "test.db")
	if err := os.WriteFile(path, template, 0o600); err != nil {
		t.Fatalf("copy the SQLite template: %v", err)
	}
	return "sqlite://" + path + sqliteTestPragmas
}

var (
	sqliteOnce  sync.Once
	sqliteBytes []byte
	sqliteErr   error

	serverMu   sync.Mutex
	serverURLs = map[database.Engine]string{}
	serverDBs  = map[database.Engine]*database.DB{}
	// serverLeases is the slot this binary holds on each server, kept so the
	// connection holding its lock stays open for the life of the process.
	serverLeases = map[database.Engine]*lease{}
)

// sqliteTestPragmas is what a test database adds to the pragmas every SQLite
// connection gets: no syncing at all. A test database is thrown away at the
// end of the test, so durability across a crash buys nothing, and SQLite's
// syncing was most of what a test cost — the API package took 37 s on
// SQLite with it and takes about one without. The journal mode is the one
// the application uses, so a test sees the same locking it does.
const sqliteTestPragmas = "?_pragma=synchronous(OFF)&_pragma=journal_mode(WAL)"

// sqliteDir returns a directory of the test's own for its SQLite file, removed
// when the test ends. The ordinary temporary directory: with syncing off the
// disk is not what a test waits on, and a memory-backed directory in a
// container is often 64 MB.
func sqliteDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// sqliteTemplate is the migrated, empty SQLite database every test in this
// binary copies, read the first time it is asked and kept as bytes: a test
// binary has no hook after its last test, and a migrated empty database is a
// few hundred kilobytes.
//
// One migration serves every binary. Each package is a binary of its own, and
// migrating once in each was 6% of the race pass's processor time — 24 s of
// 383 s sampled, a fresh install walking every migration under the detector.
// So the first binary to ask migrates and leaves the file in a directory of
// this user's, named for what built it, and the others read it.
func sqliteTemplate() ([]byte, error) {
	sqliteOnce.Do(func() {
		dir, err := templateDir()
		if err != nil {
			sqliteErr = err
			return
		}
		sqliteBytes, sqliteErr = sharedTemplate(dir)
	})
	return sqliteBytes, sqliteErr
}

// templateDir is where the shared template is kept: this user's cache,
// readable by nobody else.
//
// Not the shared temporary directory. The name is derived from files anybody
// can read, so on a machine where users share it another user can put a file
// there first, and every test binary would copy a schema nobody here migrated.
// Where there is no cache directory, the template is kept in a directory of
// this binary's own and shared with nothing.
func templateDir() (string, error) {
	if cache, err := os.UserCacheDir(); err == nil {
		dir := filepath.Join(cache, "openpsirt-dbtest")
		if err := os.MkdirAll(dir, 0o700); err == nil {
			return dir, nil
		}
	}
	return os.MkdirTemp("", "openpsirt-dbtest-")
}

// sqliteHeader opens every SQLite database file.
const sqliteHeader = "SQLite format 3\x00"

// sharedTemplate reads the template kept in dir for the migrations this
// binary carries, or migrates one and keeps it there.
//
// The name carries everything the file's content follows from, so an edited
// migration, a changed width or a new library names a different file rather
// than reading a stale one. It is written beside its name and renamed into place, so a
// binary reading it never sees half a file, and two binaries migrating at once
// each rename a complete one. A file that does not open like a database is
// migrated again.
func sharedTemplate(dir string) ([]byte, error) {
	name, err := templateName()
	if err != nil {
		return nil, err
	}
	kept := filepath.Join(dir, name)
	if held, err := os.ReadFile(kept); err == nil && strings.HasPrefix(string(held), sqliteHeader) { //nolint:gosec // G304: a name this function derives inside the temporary directory
		return held, nil
	}

	work, err := os.MkdirTemp(dir, "openpsirt-dbtest-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(work) }()
	path := filepath.Join(work, "template.db")
	if err := migrateFresh("sqlite://" + path + sqliteTestPragmas); err != nil {
		return nil, err
	}
	made, err := os.ReadFile(path) //nolint:gosec // G304: the path is one this function just chose inside its own temporary directory
	if err != nil {
		return nil, err
	}
	// Kept for the next binary where it can be, and the bytes returned either
	// way: a directory that refuses the file costs speed, not correctness.
	staged := filepath.Join(work, "staged.db")
	if err := os.WriteFile(staged, made, 0o600); err == nil { //nolint:gosec // G703: a name inside the directory MkdirTemp just made
		_ = os.Rename(staged, kept)
	}
	return made, nil
}

// templateName is the file the template is kept under: named for everything
// its content follows from — the migrations, the widths the migrations read,
// the SQLite library that writes the file and the migration library that
// writes its version table.
func templateName() (string, error) {
	schema, err := migrations.Fingerprint()
	if err != nil {
		return "", fmt.Errorf("fingerprint the migrations: %w", err)
	}
	var libraries []string
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "modernc.org/sqlite" || dep.Path == "github.com/pressly/goose/v3" {
				libraries = append(libraries, dep.Path+"@"+dep.Version)
			}
		}
	}
	key := fmt.Sprintf("%s\x00%s\x00%d\x00%d", schema, strings.Join(libraries, "\x00"),
		database.NameWidth, database.ComposedWidth)
	sum := sha256.Sum256([]byte(key))
	return "openpsirt-dbtest-" + hex.EncodeToString(sum[:6]) + ".db", nil
}
