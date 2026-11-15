// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// serverDatabase gives this binary a database of its own on the server the
// configured URL names, migrated and empty, for as long as the process runs.
//
// The database belongs to a slot of this build's schema, and the binary leases
// the lowest slot no other binary holds on that server. The lease's lock lives
// with a connection nothing closes, so a binary that exits or crashes gives the
// slot back, and the next binary to start, of any package, takes it with its
// database. A server therefore holds as many databases per schema as the most
// binaries built from it that were alive there at once.
//
// The database is kept between binaries and between runs, and reused. Applying
// the migrations is nearly the whole cost of a server engine, and none of it
// tests anything the migration tests do not. What makes reuse safe is that the
// name carries a fingerprint of the migration sources: a schema change edits
// what declares the thing rather than adding a migration beside it, so the
// applied version does not move and only the content tells one schema from
// another. An edited migration therefore names different databases.
//
// A reused database is emptied by the first test that runs on it, as every
// test's database is, and holds identifiers that continue from wherever the
// last binary left them. One whose migrations stopped part way is built again,
// described at prepareServer.
func serverDatabase(engine database.Engine, base string) (string, error) {
	serverMu.Lock()
	defer serverMu.Unlock()
	if own, ok := serverURLs[engine]; ok {
		return own, nil
	}
	fingerprint, err := migrations.Fingerprint()
	if err != nil {
		return "", fmt.Errorf("fingerprint the migrations: %w", err)
	}
	held, own, err := leaseDatabase(context.Background(), engine, base, harnessPrefix, fingerprint)
	if err != nil {
		return "", err
	}
	serverLeases[engine] = held
	serverURLs[engine] = own
	return own, nil
}

// prepareServer leaves the database called name, on the server base names,
// migrated to the schema this build expects, and returns its URL and whether
// it had to create the database.
//
// A kept database is used as it stands where it holds that schema whole. A
// run killed while it migrated leaves one holding less — a version short of
// the expected one, or no version at all — and that database is dropped and
// built again rather than migrated forward: on MySQL and MariaDB a schema
// statement commits on its own, so a migration interrupted part way leaves
// statements applied that no recorded version accounts for.
func prepareServer(ctx context.Context, engine database.Engine, base, name string) (string, bool, error) {
	own, err := databaseURL(base, engine, name)
	if err != nil {
		return "", false, err
	}
	admin, _, err := connect(ctx, base)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = admin.Close() }()
	kept, err := ensureDatabase(ctx, admin, engine, name)
	if err != nil {
		return "", false, err
	}
	transient(ctx, admin, engine)
	if kept {
		if whole(ctx, own) {
			return own, false, nil
		}
		if err := rebuild(ctx, admin, name); err != nil {
			return "", false, err
		}
	}
	serverBuilds.Add(1)
	if err := migrateFresh(own); err != nil {
		return "", false, err
	}
	return own, !kept, nil
}

// databaseURL is the URL of the database called name on the server base
// names.
//
// Parsed by the database package first: its refusal never repeats the URL,
// and the plain parser's quotes it, password included.
func databaseURL(base string, engine database.Engine, name string) (string, error) {
	target, err := database.ParseURL(base)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse the %s URL at %s", engine, target.Redacted)
	}
	parsed.Path = "/" + name
	if engine == database.Postgres {
		query := parsed.Query()
		query.Set("options", "-c synchronous_commit=off")
		// A space is written %20. The encoder writes it as "+", which pgx
		// reads as a plus sign.
		parsed.RawQuery = strings.ReplaceAll(query.Encode(), "+", "%20")
	}
	return parsed.String(), nil
}

// whole reports whether the database at url holds every migration this build
// carries. A database that cannot say is not whole: it is one this harness
// made, and building it again costs a migration.
func whole(ctx context.Context, url string) bool {
	db, _, err := connect(ctx, url)
	if err != nil {
		return false
	}
	defer func() { _ = db.Close() }()
	applied, err := schema.Version(ctx, db)
	if err != nil {
		return false
	}
	expected, err := schema.Expected()
	return err == nil && applied == expected
}

// rebuild drops the database called name and creates it empty.
//
// The drop is tried again for a few seconds. PostgreSQL refuses to drop a
// database while a session is connected to it, and a connection closed a
// moment ago may still hold its session on the server.
func rebuild(ctx context.Context, admin *database.DB, name string) error {
	var err error
	for range 50 {
		if _, err = admin.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+name+`"`); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("drop %s, which an interrupted run left half built: %w", name, err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		return fmt.Errorf("create %s again: %w", name, err)
	}
	return nil
}

// serverConnection is a handle on the one pool every test in this binary uses
// on engine. The pool is opened the first time it is asked for and never
// closed: a test binary has no hook after its last test, and the process
// ending closes it.
//
// One pool rather than one per test, because a PostgreSQL connection is a
// process of its own on the server, and a new one knows nothing of the schema.
// Its first statement against the schema costs 43 ms and the same statement
// on a warm connection 3.4 ms: the API package spends 90 s on PostgreSQL with a
// pool per test and 48 s with one.
// Tests in a package run one after another on a server, so sharing the pool
// shares nothing a test can see: the rows are emptied before each test.
//
// Each call wraps the pool in a query builder of its own. A test may add a
// query hook to the handle it is given, to count statements, and a hook added
// to a shared builder would go on firing in every later test.
func serverConnection(engine database.Engine, own string) (*database.DB, error) {
	serverMu.Lock()
	defer serverMu.Unlock()
	pool, ok := serverDBs[engine]
	if !ok {
		var err error
		if pool, _, err = connect(context.Background(), own); err != nil {
			return nil, err
		}
		serverDBs[engine] = pool
	}
	return &database.DB{DB: bun.NewDB(pool.DB.DB, pool.Dialect()), Server: pool.Server, Pool: pool.Pool}, nil
}

// ensureDatabase creates the database called name if it is not there, and
// reports whether it already was, which is the difference between migrating it
// and emptying it. Databases of other names are left, whatever schema built
// them: another binary may hold one.
func ensureDatabase(ctx context.Context, admin *database.DB, engine database.Engine, name string) (bool, error) {
	existing, err := databasesFor(ctx, admin, engine, name)
	if err != nil {
		return false, err
	}
	if slices.Contains(existing, name) {
		return true, nil
	}
	// Quoted, as every identifier is; the MySQL connections accept the
	// standard quote.
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		return false, fmt.Errorf("create %s: %w", name, err)
	}
	return false, nil
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
//
// Asked for, never assumed. The settings outlive the run and reach every
// database on the server, and a test URL may name a server that holds other
// databases, so the harness changes them only where relaxDurabilityEnv says
// the server is a throwaway: `make engines-up` writes it beside the URLs of
// the containers it starts, and CI sets it beside its own.
func transient(ctx context.Context, admin *database.DB, engine database.Engine) {
	if engine != database.MySQL && engine != database.MariaDB {
		return
	}
	if os.Getenv(relaxDurabilityEnv) != "1" {
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
// because "_" is a wildcard to LIKE and the harness's names carry it.
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

// connect opens the database at raw. A refusal to parse is the database
// package's own, which never repeats the URL; a refusal to open names the URL
// with its password taken out.
func connect(ctx context.Context, raw string) (*database.DB, database.Target, error) {
	target, err := database.ParseURL(raw)
	if err != nil {
		return nil, database.Target{}, err
	}
	if target.Engine == database.MySQL || target.Engine == database.MariaDB {
		if target, err = database.ParseURL(boundLockWait(raw)); err != nil {
			return nil, database.Target{}, err
		}
	}
	db, err := database.Open(ctx, target)
	if err != nil {
		return nil, target, fmt.Errorf("open %s: %w", target.Redacted, err)
	}
	return db, target, nil
}

// lockWait is how long a harness session on MySQL or MariaDB waits for a
// metadata lock before its statement fails. The servers' own default is a
// year on MySQL and a day on MariaDB, so a server wedged on a lock it never
// grants hangs every statement that needs it until the test binary's timeout,
// naming nothing; bounded, the statement waiting fails and is named.
const lockWait = 60 * time.Second

// boundLockWait is a MySQL or MariaDB URL with its sessions' lock_wait_timeout
// set to lockWait, unless the URL sets one itself. The driver sets every
// parameter it does not know as a session variable on each connection it
// opens, so every connection of the pool carries it.
func boundLockWait(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Query().Has("lock_wait_timeout") {
		return raw
	}
	// Appended to the URL as written, which keeps every other byte of it.
	bound := "lock_wait_timeout=" + strconv.Itoa(int(lockWait/time.Second))
	switch {
	case u.RawQuery == "" && !strings.Contains(raw, "?"):
		return raw + "?" + bound
	case strings.HasSuffix(raw, "?") || strings.HasSuffix(raw, "&"):
		return raw + bound
	default:
		return raw + "&" + bound
	}
}

// migrateFresh applies every migration to the database at url and closes it.
func migrateFresh(url string) error {
	ctx := context.Background()
	db, target, err := connect(ctx, url)
	if err != nil {
		return err
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := schema.Up(ctx, db, quiet); err != nil {
		_ = db.Close()
		return fmt.Errorf("migrate %s: %w", target.Redacted, err)
	}
	return db.Close()
}
