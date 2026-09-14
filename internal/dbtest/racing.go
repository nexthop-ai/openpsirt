package dbtest

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// A handle whose next commit loses a race, for pinning what a retry must not
// carry over.
//
// Nothing else in the tree can make a transaction fail the way a cluster makes
// one fail: the failure arrives at COMMIT, on a transaction whose every
// statement already succeeded, and it is the ordinary failure on a cluster
// rather than an exotic one. Without a handle that can produce it, the code
// that runs when it happens is reachable by no test at all.
//
// SQLite underneath, because what is being pinned does not vary by engine —
// the retry is driven by the error, and the error is synthesized here.

// Race wraps a connector and fails one commit, then gets out of the way.
type Race struct {
	driver.Connector
	mu sync.Mutex
	// armed is how many commits still have to lose. Counted rather than a
	// flag, so a test can arm it before a call that commits more than once.
	armed int
	// between runs after the commit is refused and before the retry, which is
	// where a test puts whatever the other worker did in the meantime.
	between func()
}

func (l *Race) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := l.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &raceConn{Conn: conn, owner: l}, nil
}

// take reports whether this commit is one of the ones that must lose, and
// hands back what to run before the retry.
func (l *Race) take() (bool, func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.armed <= 0 {
		return false, nil
	}
	l.armed--
	return true, l.between
}

// Arm says how many of the coming commits lose.
func (l *Race) Arm(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.armed = n
}

// Unspent is how many armed commits never happened.
//
// Asserted rather than assumed, because a path that commits nothing cannot
// lose a race and would pass every assertion below it without ever running
// the code they are about. A write outside a transaction is exactly that
// path, and it is what these tests exist to keep the queue off.
func (l *Race) Unspent() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.armed
}

type raceConn struct {
	driver.Conn
	owner *Race
}

func (c *raceConn) Begin() (driver.Tx, error) {
	//nolint:staticcheck // SA1019: the interface the wrapped driver offers.
	tx, err := c.Conn.Begin()
	if err != nil {
		return nil, err
	}
	return &raceTx{Tx: tx, owner: c.owner}, nil
}

func (c *raceConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return c.Begin()
	}
	tx, err := beginner.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &raceTx{Tx: tx, owner: c.owner}, nil
}

type raceTx struct {
	driver.Tx
	owner *Race
}

// Commit refuses once, in the words the retry helper recognizes on this
// engine, and rolls the work back the way a refused commit does.
func (t *raceTx) Commit() error {
	lost, between := t.owner.take()
	if !lost {
		return t.Tx.Commit()
	}
	if err := t.Rollback(); err != nil {
		return err
	}
	if between != nil {
		between()
	}
	return errors.New("database is locked")
}

// Racing opens a handle whose next armed commit loses a race, over a database
// of its own with the schema applied.
//
// between runs after the commit is refused and before the retry, which is
// where a caller puts whatever another worker did in the meantime.
func Racing(t *testing.T, between func()) (*database.DB, *Race) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "queue.db")

	base, err := (&sqliteConnector{dsn: file}).connector()
	if err != nil {
		t.Fatal(err)
	}
	owner := &Race{Connector: base, between: between}
	handle := &database.DB{
		DB:     bun.NewDB(sql.OpenDB(owner), sqlitedialect.New()),
		Server: database.Server{Engine: database.SQLite},
	}
	t.Cleanup(func() { _ = handle.Close() })

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := schema.Up(context.Background(), handle, quiet); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return handle, owner
}

// sqliteConnector reaches the registered driver without importing it twice.
type sqliteConnector struct{ dsn string }

func (s *sqliteConnector) connector() (driver.Connector, error) {
	opened, err := sql.Open("sqlite", s.dsn)
	if err != nil {
		return nil, err
	}
	defer func() { _ = opened.Close() }()
	return &dsnConnector{dsn: s.dsn, driver: opened.Driver()}, nil
}

type dsnConnector struct {
	dsn    string
	driver driver.Driver
}

func (d *dsnConnector) Connect(context.Context) (driver.Conn, error) {
	return d.driver.Open(d.dsn)
}

func (d *dsnConnector) Driver() driver.Driver { return d.driver }
