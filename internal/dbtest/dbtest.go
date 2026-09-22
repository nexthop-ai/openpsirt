// Package dbtest runs a test against every database available to it.
//
// SQLite always runs, so the suite is useful with nothing installed. The
// production engines run when the environment points at them, and are skipped
// loudly otherwise — a skipped engine is reported rather than silently absent,
// because a portability suite that quietly tests one engine is worse than none.
//
// The schema is built once per test binary, not once per test. A test binary
// is one package, so on SQLite one file is migrated on first use and copied
// for each test — a copy is milliseconds where eighteen migrations were about
// a second — and on the three servers each binary gets a database of its own,
// named for the package, dropped and created on first use and migrated once.
// Packages therefore share nothing and can run in parallel; tests within a
// package share the database and empty it between them with Reset, as before.
//
// A package whose tests start from the same rows declares them once as a
// Seeded template. On SQLite the seed is applied to the template before the
// first copy, so the rows cost nothing per test; on a server it is applied per
// test, after the database is emptied.
//
// Tests within a package run beside each other when SQLite is the only engine
// in the run, because SQLite is the only engine where each test already holds
// a database of its own. See the note at run.
package dbtest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/engines"
	"github.com/nexthop-ai/openpsirt/internal/schema"
	"github.com/uptrace/bun"
)

// URL environment variables for the production engines. Absent means skip.
const (
	PostgresURLEnv = "OPENPSIRT_TEST_POSTGRES_URL"
	MySQLURLEnv    = "OPENPSIRT_TEST_MYSQL_URL"
	MariaDBURLEnv  = "OPENPSIRT_TEST_MARIADB_URL"
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
// Every path here hands back a migrated schema — SQLite copies a template that
// was migrated once per binary, and each server database is either migrated on
// creation or emptied on reuse — so a test needs no schema.Up of its own. Call
// Reset only where a test leaves rows a later one must not see.
//
// This is for a test that pins what a query does: every portability defect
// found so far was a query behaving differently on one engine, so a store
// test earns all four. Each subtest gets its own connection, and it is
// closed afterwards.
func Each(t *testing.T, fn func(t *testing.T, db *database.DB)) {
	t.Helper()
	run(t, plain(fn), nil, beside, nil)
}

// Alone is Each for a test that cannot run beside another in its package.
//
// The database arrives migrated and empty of the previous test's rows.
// Every path here hands back a migrated schema — SQLite copies a template that
// was migrated once per binary, and each server database is either migrated on
// creation or emptied on reuse — so a test needs no schema.Up of its own. Call
// Reset only where a test leaves rows a later one must not see.
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
// Every path here hands back a migrated schema — SQLite copies a template that
// was migrated once per binary, and each server database is either migrated on
// creation or emptied on reuse — so a test needs no schema.Up of its own. Call
// Reset only where a test leaves rows a later one must not see.
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
// give it: its pool is one connection, so a second writer waits for a
// connection the first is holding and the test deadlocks rather than racing.
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
// Every path here hands back a migrated schema — SQLite copies a template that
// was migrated once per binary, and each server database is either migrated on
// creation or emptied on reuse — so a test needs no schema.Up of its own. Call
// Reset only where a test leaves rows a later one must not see.
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

// seeder is a Seeded template of any type, which is what run needs of one.
type seeder interface {
	// sqlite is the seeded template's bytes and what the seed made, built
	// once per binary.
	sqlite() ([]byte, any, error)
	// server seeds an emptied server database for one test.
	server(ctx context.Context, db *database.DB) (any, error)
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
		t.Parallel()
	}

	for _, c := range candidates() {
		t.Run(string(c.name), func(t *testing.T) {
			if only != nil && !only[c.name] {
				t.Skipf("%s is not asked for by this kind of test", c.name)
			}
			if wanted != nil && !wanted[c.name] {
				t.Skipf("%s is excluded by %s", c.name, EnginesEnv)
			}
			base := ""
			if c.env != "" {
				base = os.Getenv(c.env)
				if base == "" {
					t.Skipf("%s is not set, so %s is untested here", c.env, c.name)
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
			db := Open(t, own)
			var made any
			if seed != nil {
				// The package's one database on this server holds whatever
				// the previous test left, so it is emptied and seeded again
				// for each test: the copy that makes the seed free on SQLite
				// has no counterpart on a server.
				if err := clear(t.Context(), db); err != nil {
					t.Fatalf("empty the %s database before seeding it: %v", c.name, err)
				}
				if made, err = seed.server(t.Context(), db); err != nil {
					t.Fatalf("seed the %s database: %v", c.name, err)
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
	target, err := database.ParseURL(url)
	if err != nil {
		t.Fatalf("parse %q: %v", url, err)
	}
	db, err := database.Open(context.Background(), target)
	if err != nil {
		t.Fatalf("open %s: %v", target.Redacted, err)
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

// sqliteTemplate migrates one file per binary, the first time it is asked,
// and keeps its bytes rather than the file: a test binary has no hook after
// its last test, so a file would outlive it, and a migrated empty database
// is a few hundred kilobytes.
func sqliteTemplate() ([]byte, error) {
	sqliteOnce.Do(func() {
		dir, err := os.MkdirTemp("", "openpsirt-dbtest-")
		if err != nil {
			sqliteErr = err
			return
		}
		defer func() { _ = os.RemoveAll(dir) }()
		path := filepath.Join(dir, "template.db")
		if sqliteErr = migrateFresh("sqlite://" + path + sqliteTestPragmas); sqliteErr != nil {
			return
		}
		sqliteBytes, sqliteErr = os.ReadFile(path) //nolint:gosec // G304: the path is one this function just chose inside its own temporary directory
	})
	return sqliteBytes, sqliteErr
}

// serverDatabase gives this binary its own database on the server the
// configured URL names, migrated and empty. Named for the package so that two
// packages never share tables, and for the checkout so that two worktrees do
// not either.
//
// The database is kept between runs and reused. Applying the migrations is
// nearly the whole cost of a server engine — 11.2 s on MySQL and 6.2 s on
// MariaDB, once per package per engine, which is 475 s of server work in a run
// that spends 43 s of processor time — and none of it tests anything the
// migration tests do not. What makes reuse safe is that the name carries a
// fingerprint of the migration sources: a schema change edits the migration
// that created the thing rather than adding one beside it, so the applied
// version does not move and only the content tells one schema from another. An
// edited migration therefore names a different database, and the databases the
// older fingerprints named are dropped as the new one is created, so a server
// does not accumulate them.
//
// A reused database still holds the last run's rows, so it is emptied here —
// the first test in a package must see the same empty database whether or not
// somebody ran it before.
//
// Two runs of the same package from the same checkout against the same server
// at once would collide; nothing here prevents that, and it is stated so it is
// not discovered.
func serverDatabase(engine database.Engine, base string) (string, error) {
	serverMu.Lock()
	defer serverMu.Unlock()
	if own, ok := serverURLs[engine]; ok {
		return own, nil
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", engine, err)
	}
	name, err := packageDatabaseName()
	if err != nil {
		return "", err
	}

	target, err := database.ParseURL(base)
	if err != nil {
		return "", err
	}
	ctx := context.Background()
	admin, err := database.Open(ctx, target)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", target.Redacted, err)
	}
	kept, err := ensureDatabase(ctx, admin, engine, name)
	if err != nil {
		_ = admin.Close()
		return "", err
	}
	transient(ctx, admin, engine)
	if err := admin.Close(); err != nil {
		return "", err
	}

	parsed.Path = "/" + name
	if engine == database.Postgres {
		query := parsed.Query()
		query.Set("options", "-c synchronous_commit=off")
		parsed.RawQuery = query.Encode()
	}
	own := parsed.String()
	if kept {
		if err := clearFresh(own); err != nil {
			return "", err
		}
	} else if err := migrateFresh(own); err != nil {
		return "", err
	}
	serverURLs[engine] = own
	return own, nil
}

// ensureDatabase leaves exactly one database for this package and checkout on
// the server: the one named, created if it is not there. It reports whether
// the database was already present, which is the difference between migrating
// it and emptying it.
func ensureDatabase(ctx context.Context, admin *database.DB, engine database.Engine, name string) (bool, error) {
	existing, err := databasesFor(ctx, admin, engine, packagePrefix(name))
	if err != nil {
		return false, err
	}
	kept := false
	for _, other := range existing {
		if other == name {
			kept = true
			continue
		}
		// Built by migrations this checkout no longer has. Quoted, as every
		// identifier is; the MySQL connections accept the standard quote.
		if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+other+`"`); err != nil {
			return false, fmt.Errorf("drop the database an older schema left: %w", err)
		}
	}
	if !kept {
		if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
			return false, fmt.Errorf("create %s: %w", name, err)
		}
	}
	return kept, nil
}

// transient asks a server to stop flushing to disk at every commit.
//
// A test database is created here and dropped by a later run, and a crash in
// the middle of a suite is answered by running the suite again, so the
// durability a commit waits for buys nothing. What it costs is most of the
// run: the three server engines take 240 s with it and 77 s without, and per
// engine PostgreSQL 90 s against 60 s, MySQL 59 s against 12 s, MariaDB 19 s
// against 12 s. Nothing a test can observe changes — the settings govern what
// survives a crash, not what a statement returns or what a transaction sees.
//
// PostgreSQL is absent because its setting is one a session makes for itself,
// and the connection string asks for it. The two here are global on a
// MySQL-protocol server, so there is no session to ask.
//
// A connection without the privilege to set a global leaves the server as it
// is and the suite runs slower, which is the answer a speed setting deserves.
func transient(ctx context.Context, admin *database.DB, engine database.Engine) {
	if engine != database.MySQL && engine != database.MariaDB {
		return
	}
	for _, statement := range []string{
		`SET GLOBAL innodb_flush_log_at_trx_commit = 0`,
		`SET GLOBAL sync_binlog = 0`,
	} {
		_, _ = admin.ExecContext(ctx, statement)
	}
}

// databasesFor lists the databases whose names start with prefix.
//
// The two spellings are the whole of the engine-specific code here, and there
// is no portable third: PostgreSQL keeps databases in a catalog of its own,
// where the standard information schema describes only the one connected to.
//
// LIKE narrows the question at the server; the prefix is checked again here
// because "_" is a wildcard to LIKE and every one of these names carries four
// of them.
func databasesFor(ctx context.Context, admin *database.DB, engine database.Engine, prefix string) ([]string, error) {
	query := `SELECT "schema_name" FROM "information_schema"."schemata" WHERE "schema_name" LIKE ?`
	if engine == database.Postgres {
		query = `SELECT "datname" FROM "pg_database" WHERE "datname" LIKE ?`
	}
	rows, err := admin.QueryContext(ctx, query, prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("list the databases under %s: %w", prefix, err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

// packageDatabaseName names a database for the package this binary tests:
// the package's own name for a person reading the server's list, a hash of its
// import path and of the directory it is tested from, and a hash of the
// migrations that build the schema inside it.
//
// The directory is in the hash because the import path is not enough. Two
// checkouts of this repository — a second worktree, say — hold the same
// package at the same import path, and pointed at the same servers they got
// the same name, so one dropped the other's database while it was in use.
// A test binary runs in the directory of the package it tests, and that
// directory includes the checkout's path, which tells the two apart.
func packageDatabaseName() (string, error) {
	path := os.Args[0]
	if info, ok := debug.ReadBuildInfo(); ok && info.Path != "" {
		path = info.Path
	}
	dir, err := os.Getwd()
	if err != nil {
		dir = ""
	}
	schema, err := migrations.Fingerprint()
	if err != nil {
		return "", fmt.Errorf("fingerprint the migrations: %w", err)
	}
	return databaseName(path, dir, schema), nil
}

// databaseName is the name for the package at path, tested from dir, with a
// schema built by the migrations that fingerprint identifies. Short enough for
// every engine's limit on identifier length.
func databaseName(path, dir, fingerprint string) string {
	base := strings.TrimSuffix(filepath.Base(path), ".test")
	base = notIdentifier.ReplaceAllString(strings.ToLower(base), "_")
	if len(base) > 24 {
		base = base[:24]
	}
	sum := sha256.Sum256([]byte(path + "\x00" + dir))
	schema := sha256.Sum256([]byte(fingerprint))
	return "openpsirt_t_" + base + "_" + hex.EncodeToString(sum[:3]) + "_" + hex.EncodeToString(schema[:3])
}

// packagePrefix is everything in a name before the schema's fingerprint: this
// package, in this checkout. Every database under it was built for these tests,
// by one set of migrations or another.
func packagePrefix(name string) string {
	return name[:strings.LastIndex(name, "_")+1]
}

var notIdentifier = regexp.MustCompile(`[^a-z0-9_]+`)

// clearFresh empties the database at url and closes it. Used where the
// connection the tests will run on does not exist yet.
func clearFresh(url string) error {
	target, err := database.ParseURL(url)
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := database.Open(ctx, target)
	if err != nil {
		return fmt.Errorf("open %s: %w", target.Redacted, err)
	}
	if err := clear(ctx, db); err != nil {
		_ = db.Close()
		return fmt.Errorf("empty %s: %w", target.Redacted, err)
	}
	return db.Close()
}

// migrateFresh applies every migration to the database at url and closes it.
func migrateFresh(url string) error {
	target, err := database.ParseURL(url)
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := database.Open(ctx, target)
	if err != nil {
		return fmt.Errorf("open %s: %w", target.Redacted, err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := schema.Up(ctx, db, quiet); err != nil {
		_ = db.Close()
		return fmt.Errorf("migrate %s: %w", target.Redacted, err)
	}
	return db.Close()
}

// Tables is every table the migrations make, in an order safe to delete from.
//
// Exported so that a test about the schema as a whole can be about the schema
// as a whole. The full-rollback test named a handful of them by hand and
// passed over the rest, so a Down that forgot its DROP was caught for whichever
// tables somebody had thought of — and the list this returns is the one a test
// in this package holds to the migrated schema in both directions, which is
// what makes it the whole of them rather than what was remembered.
func Tables() []string { return slices.Clone(tables) }

// tables lists every table, in an order safe to delete from: children before
// the rows they reference.
//
// Add new tables at the top. A table missing from this list leaves rows
// behind between tests, and one in the wrong position fails on the engines
// that enforce foreign keys during a bulk delete — which is not all of them,
// so it will look engine-specific rather than like the ordering mistake it is.
var tables = []string{
	// Before person, product, vulnerability and flaw_report, all of which it
	// points at.
	"attachment",
	// Points at nothing, so its position says nothing.
	"lease",
	// Before outbound, which it points at, and before notification, which it
	// also points at. The delivery row cascades with the notification, so the
	// order is belt as well as braces.
	"outbound_delivery",
	// Before person, which it points at.
	"notification",
	// Before person and target, both of which it points at.
	"upgrade",
	// Before person, vulnerability and product, all of which it points at.
	"disclosure_movement",
	// Before product, vulnerability, component and person, all of which it
	// points at.
	"finding_tag",
	// Before person and product, both of which it points at.
	"saved_filter",
	// Before the comment it belongs to.
	"claim_comment_revision",
	"claim_comment",
	"vulnerability_reference",
	// Points at itself, which no position in this list can answer: a carried
	// agreement names the one it came from. The key is declared to null
	// rather than to block, so emptying the table needs no ordering.
	"claim_approval",
	"decision",
	// After the rows that point at it, and before the claim it hangs off.
	"claim_revision",
	// Before person, which it points at, and after everything above, which
	// points at it.
	"claim",
	// Before the note it belongs to.
	"issue_note_revision",
	// Before person, product and vulnerability, all of which it points at.
	"issue_note",
	// Before person, product and vulnerability, all of which it points at.
	// Nothing points at it: a record of being exploited is referenced by
	// nobody, which is what makes it safe anywhere above those three.
	"exploited_here",
	// Before person, product and vulnerability, which it points at.
	"assessment",
	// Before product and vulnerability, both of which it points at.
	"issue_rating",
	"personal_token",
	"person_identity",
	"group_admin",
	"group_role",
	"session",
	"api_key",
	"role_grant_all",
	"role_grant",
	// Before person and product, which they point at.
	"vex_statement",
	// Before target and person, both of which it points at.
	"vex_issuance",
	// Before person, which they point at.
	"admin_change",
	// Before team, person and product, all of which it points at.
	"routing_rule",
	// Before person, product and vulnerability, all of which it points at.
	"case_collaborator",
	// Before flaw_report and report_ruling, both of which it points at.
	"report_ruled",
	// Before report_ruling, person, vulnerability and product, all of which
	// it points at.
	"flaw_report",
	// Before person, vulnerability and product, all of which it points at.
	"report_ruling",
	// Before advisory_edition, advisory and person, all of which it points
	// at. The edition is what went out, which is a fact about a moment.
	"advisory_issuance",
	// Before advisory, product, vulnerability and person, all of which it
	// points at.
	"advisory_issue",
	// Before advisory_edition, advisory and person, all of which it points
	// at.
	"advisory_approval",
	// Before advisory and person, both of which it points at. The advisory
	// points back at an edition with no foreign key, so only this direction
	// has an order to keep.
	"advisory_edition",
	// After the four above, which point at it, and before person.
	"advisory",
	// Before person, which it points at.
	"outbound",
	// Before team and person, both of which they point at.
	"team_member",
	"team",
	"person",
	// After person and team, which point at it.
	"party",
	"finding",
	"suppression",
	"scan_run",
	"vulnerability_alias",
	"vulnerability_weakness",
	"vulnerability",
	"scan_document_chunk",
	"scan_document",
	"graph_edge",
	"graph_node",
	"component",
	"job",
	"scan_refusal",
	"scan",
	"target",
	"variant",
	"stream",
	"product",
	"application_setting",
}

// TablesIn is every table the migrations made, sorted, read from the database
// rather than from the migration source.
//
// SQLite only: the three server engines spell this question three other ways,
// and the answer does not vary by engine — the migrations are one list of
// statements and what differs between engines is the column types. A caller
// that wants it on a server engine wants a different question.
//
// It fails rather than returning nothing, because an empty answer and a
// database nobody migrated look the same to every caller.
func TablesIn(t *testing.T, ctx context.Context, db *database.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx,
		`SELECT "name" FROM "sqlite_master" WHERE "type" = 'table' AND "name" NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var made []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		made = append(made, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(made) == 0 {
		t.Fatal("the schema declared no tables, so this checked nothing")
	}
	slices.Sort(made)
	return made
}

// Reset empties every table, leaving the schema in place.
//
// It lives here rather than in each test package so that adding a table is one
// change instead of one per package. A new table with a foreign key otherwise
// breaks the cleanup of every package that predates it, silently.
func Reset(t *testing.T, db *database.DB) {
	t.Helper()
	if err := clear(context.Background(), db); err != nil {
		t.Fatalf("reset: %v", err)
	}
}

// clear is Reset without a test to fail: the harness empties a database it
// kept from an earlier run before any test sees it.
func clear(ctx context.Context, db *database.DB) error {
	// One transaction, not thirty statements. SQLite in its default mode syncs
	// the file at every commit, and thirty commits of that between every pair
	// of tests is a large part of what a test on SQLite costs.
	//
	// And one statement per table that holds something, rather than one per
	// table. A statement costs a round trip whether or not it changes a row —
	// 203 µs on MariaDB, 404 µs on PostgreSQL, 2,835 µs on MySQL — and a test
	// touches a handful of the fifty-odd tables, so most of the work is
	// emptying tables that are already empty. Which ones hold anything is one
	// more statement, asked before the deletes and inside the same transaction.
	return database.InTransaction(ctx, db.DB, func(ctx context.Context, tx bun.Tx) error {
		occupied, err := occupied(ctx, tx)
		if err != nil {
			return err
		}
		// A tag points at the branch it was cut from. MySQL and MariaDB
		// enforce that self-reference during a bulk delete even though every
		// row is going; PostgreSQL and SQLite happen not to.
		if occupied["stream"] {
			if _, err := tx.ExecContext(ctx, `UPDATE "stream" SET "parent_id" = NULL`); err != nil {
				return fmt.Errorf("detach stream parents: %w", err)
			}
		}
		// A claim points at the claim it was derived from, which is the same
		// shape and the same two engines.
		if occupied["claim"] {
			if _, err := tx.ExecContext(ctx, `UPDATE "claim" SET "derived_from" = NULL`); err != nil {
				return fmt.Errorf("detach derived claims: %w", err)
			}
		}
		for _, table := range tables {
			if !occupied[table] {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM "`+table+`"`); err != nil {
				return fmt.Errorf("clear %s: %w", table, err)
			}
		}
		return nil
	})
}

// occupied names the tables holding at least one row, in one statement.
//
// A row per table would be one round trip per table, which is the cost this
// exists to avoid, so it is one row of one column per table: a scalar subquery
// answering 1 where the table has anything and NULL where it has not. LIMIT 1
// rather than COUNT, because the question is whether a delete has anything to
// do and a table under test can hold a quarter of a million rows.
func occupied(ctx context.Context, tx bun.Tx) (map[string]bool, error) {
	columns := make([]string, len(tables))
	for i, table := range tables {
		columns[i] = fmt.Sprintf(`(SELECT 1 FROM "%s" LIMIT 1) AS "held_%d"`, table, i)
	}
	held := make([]sql.NullInt64, len(tables))
	into := make([]any, len(tables))
	for i := range held {
		into[i] = &held[i]
	}
	if err := tx.QueryRowContext(ctx, "SELECT "+strings.Join(columns, ", ")).Scan(into...); err != nil {
		return nil, fmt.Errorf("ask which tables hold rows: %w", err)
	}
	occupied := make(map[string]bool, len(tables))
	for i, table := range tables {
		occupied[table] = held[i].Valid
	}
	return occupied, nil
}
