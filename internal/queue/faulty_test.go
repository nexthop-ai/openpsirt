package queue_test

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
	"github.com/nexthop-ai/openpsirt/internal/queue"
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

// losesARace wraps a connector and fails one commit, then gets out of the way.
type losesARace struct {
	driver.Connector
	mu sync.Mutex
	// armed is how many commits still have to lose. Counted rather than a
	// flag, so a test can arm it before a call that commits more than once.
	armed int
	// between runs after the commit is refused and before the retry, which is
	// where a test puts whatever the other worker did in the meantime.
	between func()
}

func (l *losesARace) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := l.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &racingConn{Conn: conn, owner: l}, nil
}

// take reports whether this commit is one of the ones that must lose, and
// hands back what to run before the retry.
func (l *losesARace) take() (bool, func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.armed <= 0 {
		return false, nil
	}
	l.armed--
	return true, l.between
}

// arm says how many of the coming commits lose.
func (l *losesARace) arm(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.armed = n
}

// unspent is how many armed commits never happened.
//
// Asserted rather than assumed, because a path that commits nothing cannot
// lose a race and would pass every assertion below it without ever running
// the code they are about. A write outside a transaction is exactly that
// path, and it is what these tests exist to keep the queue off.
func (l *losesARace) unspent() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.armed
}

type racingConn struct {
	driver.Conn
	owner *losesARace
}

func (c *racingConn) Begin() (driver.Tx, error) {
	//nolint:staticcheck // SA1019: the interface the wrapped driver offers.
	tx, err := c.Conn.Begin()
	if err != nil {
		return nil, err
	}
	return &racingTx{Tx: tx, owner: c.owner}, nil
}

func (c *racingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return c.Begin()
	}
	tx, err := beginner.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &racingTx{Tx: tx, owner: c.owner}, nil
}

type racingTx struct {
	driver.Tx
	owner *losesARace
}

// Commit refuses once, in the words the retry helper recognizes on this
// engine, and rolls the work back the way a refused commit does.
func (t *racingTx) Commit() error {
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

// racing opens a queue over a handle that will lose one commit.
func racing(t *testing.T, between func()) (*database.DB, *losesARace) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "queue.db")

	base, err := (&sqliteConnector{dsn: file}).connector()
	if err != nil {
		t.Fatal(err)
	}
	owner := &losesARace{Connector: base, between: between}
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

func TestAClaimThatWasRolledBackIsNotReturned(t *testing.T) {
	// A commit refused for a reason worth retrying re-runs the whole closure.
	// The claim it had already made is gone, because the transaction that
	// made it was rolled back — so if the job it scanned survives into the
	// next attempt, a worker is handed a claim the database does not have and
	// runs work somebody else holds. On an ingest that looks like real change
	// rather than an error.
	//
	// The ordinary failure on a cluster, not an exotic one: a certification
	// failure arrives at COMMIT on a transaction whose every statement had
	// already succeeded.
	ctx := t.Context()

	var handle *database.DB
	var owner *losesARace
	handle, owner = racing(t, func() {
		// What the other worker did while the first attempt was losing: it
		// finished the job, so there is nothing left for the retry to claim.
		if _, err := handle.ExecContext(context.WithoutCancel(ctx),
			`UPDATE "job" SET "state" = 'done'`); err != nil {
			t.Errorf("marking the job done between attempts: %v", err)
		}
	})

	q := queue.New(handle, queue.DefaultOptions())
	if _, err := q.Add(ctx, "ingest", "the-only-job"); err != nil {
		t.Fatal(err)
	}

	owner.arm(1)
	job, err := q.Claim(ctx, "worker", "ingest")
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}
	if job != nil {
		t.Errorf("a claim that was rolled back came back as job %d for %q — "+
			"the work is somebody else's and this worker would run it too",
			job.ID, "worker")
	}
}

func TestACommitThatLosesARaceIsTriedAgain(t *testing.T) {
	// The other half, and the one that must not regress: losing a race is not
	// a failure, it is a reason to go again. A claim that loses one commit
	// still hands out the job.
	ctx := t.Context()
	handle, owner := racing(t, nil)

	q := queue.New(handle, queue.DefaultOptions())
	if _, err := q.Add(ctx, "ingest", "the-only-job"); err != nil {
		t.Fatal(err)
	}

	owner.arm(1)
	job, err := q.Claim(ctx, "worker", "ingest")
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}
	if job == nil {
		t.Fatal("a claim that lost one commit gave up rather than going again")
	}
	if job.Reference != "the-only-job" {
		t.Errorf("claimed %q", job.Reference)
	}
}

func TestFinishingWorkSurvivesACommitThatLosesARace(t *testing.T) {
	// A cluster certifies at COMMIT, so a write whose statements all succeeded
	// can still be rolled back under it. Reported up rather than retried, that
	// turns a job which finished into a job the caller records as failed and
	// the queue hands out again — the work runs twice, which on an ingest
	// looks like real change.
	ctx := t.Context()
	handle, owner := racing(t, nil)

	q := queue.New(handle, queue.DefaultOptions())
	if _, err := q.Add(ctx, "ingest", "finishes"); err != nil {
		t.Fatal(err)
	}
	job, err := q.Claim(ctx, "worker", "ingest")
	if err != nil || job == nil {
		t.Fatalf("claiming: %v", err)
	}

	owner.arm(1)
	if err := q.Succeed(ctx, job.ID, "worker"); err != nil {
		t.Fatalf("finishing work lost one commit and gave up: %v", err)
	}
	if owner.unspent() != 0 {
		t.Fatalf("finishing work committed nothing this could refuse, so it writes " +
			"outside a transaction and a refused commit cannot be retried at all")
	}

	var state string
	if err := handle.QueryRowContext(ctx,
		`SELECT "state" FROM "job" WHERE "id" = ?`, job.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != string(queue.Done) {
		t.Errorf("the job is %q rather than %q after finishing", state, queue.Done)
	}
}

func TestQueueingWorkSurvivesACommitThatLosesARace(t *testing.T) {
	// The same at the other end: a refused commit on the insert meant the work
	// was never queued, and the caller was told so.
	ctx := t.Context()
	handle, owner := racing(t, nil)

	q := queue.New(handle, queue.DefaultOptions())
	owner.arm(1)
	job, err := q.Add(ctx, "ingest", "queued-despite-a-lost-race")
	if err != nil {
		t.Fatalf("queueing work lost one commit and gave up: %v", err)
	}
	if job == nil {
		t.Fatal("nothing was queued")
	}
	if owner.unspent() != 0 {
		t.Fatalf("queueing work committed nothing this could refuse, so it writes " +
			"outside a transaction and a refused commit cannot be retried at all")
	}

	var queued int
	if err := handle.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM "job" WHERE "reference" = ?`, "queued-despite-a-lost-race").
		Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Errorf("%d rows were queued, want exactly one", queued)
	}
}
