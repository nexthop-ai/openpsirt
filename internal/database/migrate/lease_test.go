// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/engines"
)

// This package cannot use dbtest: dbtest builds the schema, the schema is
// applied through this package, and Go allows no such cycle in a test. So
// the two helpers it needs are here, in the smallest form that works.
//
// The engines a run may touch are *not* copied here. That rule lives
// in dbtest/engines, which imports neither this package nor dbtest, precisely
// so the copy in this file does not have to exist — it is the rule the quick
// loop and the race run set.
const (
	postgresURLEnv = "OPENPSIRT_TEST_POSTGRES_URL"
	mysqlURLEnv    = "OPENPSIRT_TEST_MYSQL_URL"
	mariadbURLEnv  = "OPENPSIRT_TEST_MARIADB_URL"
)

func open(t *testing.T, url string) *database.DB {
	t.Helper()
	target, err := database.ParseURL(url)
	if err != nil {
		t.Fatalf("parse the database URL: %v", err)
	}
	db, err := database.Open(context.Background(), target)
	if err != nil {
		t.Fatalf("open %s: %v", target.Redacted, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// shortLease makes the lease lapse a second after it is written, renewed every
// tenth of a second, its holder stopping after seven tenths unanswered, and a
// waiter trying every twentieth and saying so at once, for one test.
func shortLease(t *testing.T) {
	t.Helper()
	was := []time.Duration{leaseFor, renewEvery, stopAfter, claimEvery, waitLogEvery}
	leaseFor, renewEvery, stopAfter, claimEvery, waitLogEvery =
		time.Second, 100*time.Millisecond, 700*time.Millisecond, 50*time.Millisecond, 0
	t.Cleanup(func() {
		leaseFor, renewEvery, stopAfter, claimEvery, waitLogEvery = was[0], was[1], was[2], was[3], was[4]
	})
}

// movedClock is the database's clock as every lease reads it, run ahead by
// an amount the test moves: a lapse is reached by moving the clock, never by
// waiting for it.
type movedClock struct{ ahead atomic.Int64 }

// moveClock lets one test move the database's clock as the lease reads it.
func moveClock(t *testing.T) *movedClock {
	t.Helper()
	c := &movedClock{}
	was := leaseClock
	leaseClock = func(ctx context.Context, q database.RowQuerier, engine database.Engine) (time.Time, error) {
		now, err := was(ctx, q, engine)
		return now.Add(time.Duration(c.ahead.Load())), err
	}
	t.Cleanup(func() { leaseClock = was })
	return c
}

// move runs the clock ahead by d.
func (c *movedClock) move(d time.Duration) { c.ahead.Add(int64(d)) }

// now is the database's clock on db as the lease reads it.
func now(t *testing.T, db *database.DB) time.Time {
	t.Helper()
	at, err := leaseClock(t.Context(), db, db.Server.Engine)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// freshLease makes the lease table where it is absent, empties it, and
// empties it again when the test ends.
func freshLease(t *testing.T, db *database.DB) {
	t.Helper()
	if err := leaseTable(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	clear := func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM "`+LeaseTable+`"`) }
	clear()
	t.Cleanup(clear)
}

// leftBy writes the lease row a process that died holding it leaves, lapsing
// after a time by the database's clock.
func leftBy(t *testing.T, db *database.DB, holding string, lapsesIn time.Duration) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), `INSERT INTO "`+LeaseTable+`"
		("name", "token", "holding", "holder", "expires_at") VALUES (?, ?, ?, ?, ?)`,
		leaseName, "dead", holding, "process 1 on a host that is gone", now(t, db).Add(lapsesIn).UnixMicro()); err != nil {
		t.Fatal(err)
	}
}

// One instance holds the lease at a time on every engine: a second waits,
// naming the holder, and takes it once it is let go. Two claimants asking at
// the same moment get one lease between them, every time.
//
// It cannot be written through Up: every caller there serializes on the
// in-process mutex before reaching acquire, so a test driving goroutines
// through Up passes with the lease deleted. This drives acquire and the claim
// directly, from two pools.
func TestOneClaimantHoldsTheLeaseAtATime(t *testing.T) {
	shortLease(t)
	everyEngine(t, func(t *testing.T, engine database.Engine, address string) {
		ctx := t.Context()
		first, second := open(t, address), open(t, address)
		freshLease(t, first)

		lock, err := acquire(ctx, first)
		if err != nil {
			t.Fatalf("the first instance could not take the lease: %v", err)
		}
		// The second instance is stopped once three of its claims have found
		// the lease held.
		said := &lines{}
		waiting, stop := context.WithCancel(WithEngine(ctx, engine, said.logger()))
		defer stop()
		ended := make(chan error, 1)
		go func() {
			again, err := acquire(waiting, second)
			if err == nil {
				_ = again.release(ctx)
			}
			ended <- err
		}()
		saidTimes(t, said, waitingLine, 3, ended)
		stop()
		if err := <-ended; err == nil {
			_ = lock.release(ctx)
			t.Fatal("a second instance took the migration lease while it was held")
		}
		if want := fmt.Sprintf("process %d on ", os.Getpid()); !strings.Contains(said.String(), "waiting for the migration lease") ||
			!strings.Contains(said.String(), want) || !strings.Contains(said.String(), "lapses_unless_renewed_in") {
			t.Errorf("the wait does not name the holder and when its lease lapses: %q", said.String())
		}
		if err := lock.release(ctx); err != nil {
			t.Fatalf("release: %v", err)
		}
		again, err := acquire(ctx, second)
		if err != nil {
			t.Fatalf("the lease was not handed on once let go: %v", err)
		}
		if err := again.release(ctx); err != nil {
			t.Errorf("release by the second instance: %v", err)
		}

		// Claimants racing for a lease nobody holds, standing or lapsed.
		for round := range 20 {
			if round%2 == 1 {
				leftBy(t, first, holdingMigrate, -time.Second)
			}
			claimants := []*lease{
				{db: first, token: newToken(), holder: "first"},
				{db: second, token: newToken(), holder: "second"},
			}
			var wins atomic.Int32
			var wg sync.WaitGroup
			start := make(chan struct{})
			for _, c := range claimants {
				wg.Go(func() {
					<-start
					// A claim refused for a lost race tries again within the
					// helper; one refused past that has claimed nothing.
					if won, _, _, err := c.claim(ctx); err == nil && won {
						wins.Add(1)
					} else if err != nil && !database.WorthRetrying(err) {
						t.Errorf("round %d: a claim failed: %v", round, err)
					}
				})
			}
			close(start)
			wg.Wait()
			if got := wins.Load(); got != 1 {
				t.Fatalf("round %d: %d claimants took the lease at once", round, got)
			}
			if _, err := first.ExecContext(ctx, `DELETE FROM "`+LeaseTable+`"`); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// A lease its holder stopped renewing, as a process that died leaves it,
// holds every waiter until it lapses by the database's clock, and is taken
// over then. The waiter names the holder and when the lease lapses while it
// waits, and says it took the lease over.
//
// The lease is left lapsing an hour on, and the clock moved to the lapse once
// three claims have found it held.
func TestALeaseItsHolderLeftIsTakenOnlyOnceItLapses(t *testing.T) {
	shortLease(t)
	clock := moveClock(t)
	everyEngine(t, func(t *testing.T, engine database.Engine, address string) {
		ctx := t.Context()
		db, waiter := open(t, address), open(t, address)
		freshLease(t, db)
		const left = time.Hour
		leftBy(t, db, holdingChange, left)
		lapses := now(t, db).Add(left)

		said := &lines{}
		var lock *held
		ended := make(chan error, 1)
		go func() {
			var err error
			lock, err = acquire(WithEngine(ctx, engine, said.logger()), waiter)
			ended <- err
		}()
		saidTimes(t, said, waitingLine, 3, ended)
		clock.move(left)
		select {
		case err := <-ended:
			if err != nil {
				t.Fatalf("the waiter did not take the lease once it lapsed: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the waiter did not take the lease within 10s of its lapse")
		}
		defer func() { _ = lock.release(ctx) }()
		if took := now(t, db); took.Before(lapses) {
			t.Errorf("the lease was taken at %s, before it lapsed at %s", took, lapses)
		}
		for _, want := range []string{"waiting for the migration lease", "process 1 on a host that is gone",
			"lapses_unless_renewed_in", "took over the migration lease"} {
			if !strings.Contains(said.String(), want) {
				t.Errorf("the waiter's log does not say %q: %q", want, said.String())
			}
		}
	})
}

// A holder's renewals keep its lease past any one lapse it wrote.
//
// The clock is moved half a lapse at a time, each move followed by a renewal
// written after it, until three lapses have passed.
func TestRenewalKeepsTheLease(t *testing.T) {
	shortLease(t)
	clock := moveClock(t)
	everyEngine(t, func(t *testing.T, _ database.Engine, address string) {
		ctx := t.Context()
		db, other := open(t, address), open(t, address)
		freshLease(t, db)
		lock, err := acquire(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		for range 6 {
			clock.move(leaseFor / 2)
			renewedPast(t, db, lapseOf(t, db))
		}
		if lost := context.Cause(lock.ctx); lost != nil {
			t.Fatalf("a holder renewing its lease lost it: %v", lost)
		}
		claimant := &lease{db: other, token: newToken(), holder: "claimant"}
		if won, _, _, err := claimant.claim(ctx); err != nil || won {
			t.Fatalf("a lease renewed past three of its lapses was taken (%v, %v)", won, err)
		}
		if err := lock.release(ctx); err != nil {
			t.Errorf("a renewed lease was not held when let go: %v", err)
		}
	})
}

// lapseOf is when the lease standing in db lapses, as written.
func lapseOf(t *testing.T, db *database.DB) int64 {
	t.Helper()
	var expires int64
	if err := db.QueryRowContext(t.Context(), `SELECT "expires_at" FROM "`+LeaseTable+`" WHERE "name" = ?`,
		leaseName).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	return expires
}

// renewedPast waits up to ten seconds for the lease standing in db to be
// written lapsing later than was.
func renewedPast(t *testing.T, db *database.DB, was int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for lapseOf(t, db) <= was {
		if time.Now().After(deadline) {
			t.Fatal("the holder did not renew its lease within 10s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A holder whose lease another instance took sends no further statement:
// its context ends within a renewal, and the next statement under it is
// refused before it is sent. The migration reports the loss, and the release
// leaves the other instance's lease standing.
func TestAHolderThatLostItsLeaseStopsBeforeItsNextStatement(t *testing.T) {
	shortLease(t)
	everyEngine(t, func(t *testing.T, _ database.Engine, address string) {
		ctx := t.Context()
		db, thief := open(t, address), open(t, address)
		freshLease(t, db)
		quiet := slog.New(slog.DiscardHandler)
		err := withLock(ctx, db, quiet, func(ctx context.Context, _ *held) error {
			if _, err := thief.ExecContext(t.Context(), `UPDATE "`+LeaseTable+`" SET "token" = 'thief'`); err != nil {
				t.Fatal(err)
			}
			// Sooner than stopAfter, so only a renewal finding the lease
			// taken ends it in time, never the unanswered bound.
			select {
			case <-ctx.Done():
			case <-time.After(5 * renewEvery):
				t.Fatal("a holder whose lease was taken went on holding it")
			}
			if !errors.Is(context.Cause(ctx), errLeaseLost) {
				t.Errorf("the holder's context ended for %v, not the lost lease", context.Cause(ctx))
			}
			if _, err := db.ExecContext(ctx, `SELECT 1`); err == nil {
				t.Error("a statement ran under a lease that was lost")
			}
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "may have migrated at the same time") {
			t.Errorf("a migration that lost its lease part way answered %v", err)
		}
		var token string
		if err := thief.QueryRowContext(ctx, `SELECT "token" FROM "`+LeaseTable+`"`).Scan(&token); err != nil || token != "thief" {
			t.Errorf("the release left %q (%v), not the lease another instance took", token, err)
		}
	})
}

// On the server engines a holder whose renewals go unanswered stops before
// the lapse it last wrote, which leaves a claimant on a node whose clock runs
// ahead nothing to take early. The row is held by another session, so every
// renewal waits out its bound.
func TestAHolderWhoseRenewalsGoUnansweredStops(t *testing.T) {
	shortLease(t)
	servers(t, func(t *testing.T, _ database.Engine, address string) {
		ctx := t.Context()
		db, blocker := open(t, address), open(t, address)
		freshLease(t, db)
		lock, err := acquire(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.release(context.Background()) }()
		tx, err := blocker.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		var token string
		if err := tx.QueryRowContext(ctx, `SELECT "token" FROM "`+LeaseTable+`" FOR UPDATE`).Scan(&token); err != nil {
			t.Fatal(err)
		}
		blocked := time.Now()
		select {
		case <-lock.ctx.Done():
		case <-time.After(leaseFor + stopAfter):
			t.Fatal("a holder whose renewals went unanswered went on holding the lease")
		}
		// Halfway between stopping and the lapse, so a holder stopping at
		// the lapse, with no room for the clocks to differ, fails.
		if waited := time.Since(blocked); waited >= (stopAfter+leaseFor)/2 {
			t.Errorf("the holder stopped %s after its renewals stopped answering, leaving the clocks no room", waited)
		}
		if !errors.Is(context.Cause(lock.ctx), errLeaseLost) {
			t.Errorf("the holder stopped for %v, not the lost lease", context.Cause(lock.ctx))
		}
	})
}

// A release that finds the lease no longer its own reports it lost, so a
// migration whose lease was taken between two renewals fails, which on
// SQLite, where no time stops a holder, nothing else catches.
func TestAReleaseOfALeaseTakenSinceTheLastRenewalReportsItLost(t *testing.T) {
	everyEngine(t, func(t *testing.T, _ database.Engine, address string) {
		ctx := t.Context()
		db, thief := open(t, address), open(t, address)
		freshLease(t, db)
		lock, err := acquire(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := thief.ExecContext(ctx, `UPDATE "`+LeaseTable+`" SET "token" = 'thief'`); err != nil {
			t.Fatal(err)
		}
		if err := lock.release(ctx); !errors.Is(err, errLeaseLost) {
			t.Errorf("letting go of a lease another instance took answered %v", err)
		}
	})
}

// Instances making the lease table at once all find it made, whichever way
// the engine refuses the ones that lose: PostgreSQL may answer a racing
// create as a duplicate or as a table that already exists. The create is
// raced on its own, since asking the catalog first narrows the window to
// where a race seldom lands.
func TestInstancesMakingTheLeaseTableAtOnceAllFindItMade(t *testing.T) {
	everyEngine(t, func(t *testing.T, _ database.Engine, address string) {
		ctx := t.Context()
		pools := []*database.DB{open(t, address), open(t, address), open(t, address), open(t, address)}
		drop := func() { _, _ = pools[0].ExecContext(context.Background(), `DROP TABLE IF EXISTS "`+LeaseTable+`"`) }
		t.Cleanup(drop)
		for round := range 100 {
			drop()
			start := make(chan struct{})
			var wg sync.WaitGroup
			for _, db := range pools {
				wg.Go(func() {
					<-start
					if err := makeLeaseTable(ctx, db); err != nil {
						t.Errorf("round %d: %v", round, err)
					}
				})
			}
			close(start)
			wg.Wait()
		}
	})
}

// A create of the lease table refused as worth asking again, as MySQL refuses
// one of two racing creates with a deadlock, is asked again and makes it. The
// race itself lands too seldom to show this in any one run.
func TestALeaseTableCreateRefusedAsADeadlockIsAskedAgain(t *testing.T) {
	everyEngine(t, func(t *testing.T, _ database.Engine, address string) {
		db := open(t, address)
		drop := func() { _, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS "`+LeaseTable+`"`) }
		drop()
		t.Cleanup(drop)
		was := leaseCreate
		t.Cleanup(func() { leaseCreate = was })
		asked := 0
		leaseCreate = func(ctx context.Context, db *database.DB, statement string) error {
			asked++
			if asked < 3 {
				return &mysql.MySQLError{Number: 1213, Message: "Deadlock found when trying to get lock"}
			}
			return was(ctx, db, statement)
		}
		if err := makeLeaseTable(t.Context(), db); err != nil {
			t.Fatalf("a create refused twice as a deadlock answered %v", err)
		}
		if there, err := tableExists(t.Context(), db, LeaseTable); err != nil || !there {
			t.Errorf("the lease table is there: %v (%v), want it made", there, err)
		}
		if asked != 3 {
			t.Errorf("the create was asked %d times, want 3", asked)
		}
	})
}

// Claimants racing for a lapsed lease under MariaDB's snapshot isolation,
// the default from 11.6.2, get one lease between them: the loser is refused
// as having read a row that changed, and tries again.
func TestARaceUnderSnapshotIsolationIsTriedAgain(t *testing.T) {
	engines.SkipUnless(t, database.MariaDB)
	address := os.Getenv(mariadbURLEnv)
	if address == "" {
		t.Skipf("%s is not set", mariadbURLEnv)
	}
	ctx := t.Context()
	isolated := func() *database.DB {
		db := open(t, address)
		db.SetMaxOpenConns(1)
		db.SetConnMaxLifetime(0)
		if _, err := db.ExecContext(ctx, `SET SESSION innodb_snapshot_isolation = ON`); err != nil {
			t.Skipf("this server has no snapshot isolation to set (%v)", err)
		}
		return db
	}
	first, second := isolated(), isolated()
	freshLease(t, first)
	for round := range 20 {
		leftBy(t, first, holdingMigrate, -time.Second)
		claimants := []*lease{
			{db: first, token: newToken(), holder: "first"},
			{db: second, token: newToken(), holder: "second"},
		}
		var wins atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, c := range claimants {
			wg.Go(func() {
				<-start
				won, _, _, err := c.claim(ctx)
				if err != nil {
					t.Errorf("round %d: a claim failed: %v", round, err)
				}
				if won {
					wins.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()
		if got := wins.Load(); got != 1 {
			t.Fatalf("round %d: %d claimants took the lease", round, got)
		}
		if _, err := first.ExecContext(ctx, `DELETE FROM "`+LeaseTable+`"`); err != nil {
			t.Fatal(err)
		}
	}
}

// A waiter stops waiting when its context ends, between two claims, so a
// shutdown reaches a process waiting on another's migration. Its claims are a
// minute apart, and its context ends once the first has found the lease held.
func TestAWaitForTheLeaseEndsWhenItsContextDoes(t *testing.T) {
	was := claimEvery
	claimEvery = time.Minute
	t.Cleanup(func() { claimEvery = was })
	everyEngine(t, func(t *testing.T, engine database.Engine, address string) {
		ctx := t.Context()
		holder, waiter := open(t, address), open(t, address)
		freshLease(t, holder)
		lock, err := acquire(ctx, holder)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.release(ctx) }()

		said := &lines{}
		stopping, stop := context.WithCancel(WithEngine(ctx, engine, said.logger()))
		defer stop()
		ended := make(chan error, 1)
		go func() {
			again, err := acquire(stopping, waiter)
			if err == nil {
				_ = again.release(ctx)
			}
			ended <- err
		}()
		saidTimes(t, said, waitingLine, 1, ended)
		stop()
		select {
		case err := <-ended:
			if err == nil {
				t.Fatal("a waiter took the lease while it was held")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a waiter asked to stop went on waiting for its next claim")
		}
	})
}

// lines is what a logger wrote, safe to read while the logger writes.
type lines struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *lines) logger() *slog.Logger { return slog.New(slog.NewTextHandler(l, nil)) }

// waitingLine is what a waiter logs at each claim finding the lease held,
// while the time between lines is nothing.
const waitingLine = "waiting for the migration lease"

// saidTimes waits until the log holds line n times, and fails the test if
// what writes it ends first or ten seconds pass.
func saidTimes(t *testing.T, said *lines, line string, n int, ended <-chan error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for strings.Count(said.String(), line) < n {
		select {
		case err := <-ended:
			t.Fatalf("it ended, answering %v, before it said %q %d times: %q", err, line, n, said.String())
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("it did not say %q %d times within 10s: %q", line, n, said.String())
		}
	}
}

// The catalog probe answers absent for a table that is not there, present for
// one that is, and a failure for a database it cannot reach, on every engine.
// Absent is what a fresh database is, and a failure read as absent is a
// populated database told to migrate.
func TestAnUnreadableVersionIsNotAnEmptyDatabase(t *testing.T) {
	for name, env := range map[database.Engine]string{
		database.Postgres: postgresURLEnv,
		database.MySQL:    mysqlURLEnv,
		database.MariaDB:  mariadbURLEnv,
		database.SQLite:   "",
	} {
		t.Run(string(name), func(t *testing.T) {
			engines.SkipUnless(t, name)
			address := "sqlite://" + t.TempDir() + "/probe.db"
			if env != "" {
				if address = os.Getenv(env); address == "" {
					t.Skipf("%s is not set", env)
				}
			}
			db := open(t, address)
			ctx := context.Background()

			probe := fmt.Sprintf("probe_present_%d", time.Now().UnixNano())
			t.Cleanup(func() { _, _ = db.ExecContext(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS "`+probe+`"`) })
			there, err := tableExists(ctx, db, probe)
			if err != nil {
				t.Fatalf("probing a reachable database reported a failure: %v", err)
			}
			if there {
				t.Error("a table nobody made was reported present")
			}
			if _, err := db.ExecContext(ctx, `CREATE TABLE "`+probe+`" ("id" INTEGER)`); err != nil {
				t.Fatal(err)
			}
			if there, err := tableExists(ctx, db, probe); err != nil || !there {
				t.Errorf("a table just made was reported present %v, failing %v", there, err)
			}

			closed := open(t, address)
			if err := closed.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			if _, err := tableExists(ctx, closed, probe); err == nil {
				t.Error("a database that could not be read reported that the table is simply absent")
			}
		})
	}
}

func TestACredentialThatCannotReadTheVersionTableIsNotAnEmptyDatabase(t *testing.T) {
	// The case the whole distinction exists for. Running migrations under
	// credentials of their own is the documented reason automatic migration
	// can be turned off, so a runtime role granted per-table rights that omit
	// the bookkeeping table is the ordinary arrangement rather than an exotic
	// one, and it must not read as a database nobody has ever migrated.
	engines.SkipUnless(t, database.Postgres)
	address := os.Getenv(postgresURLEnv)
	if address == "" {
		t.Skipf("%s is not set", postgresURLEnv)
	}
	owner := open(t, address)
	ctx := context.Background()

	// A table standing in for the bookkeeping one, so this test neither
	// depends on the migrations having run nor disturbs them. The database is
	// whichever one the URL names, asked rather than assumed.
	var name string
	if err := owner.QueryRowContext(ctx, "SELECT current_database()").Scan(&name); err != nil {
		t.Fatalf("ask which database this is: %v", err)
	}
	quoted := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	probe := fmt.Sprintf("probe_unreadable_%d", time.Now().UnixNano())
	role := probe + "_role"
	// Registered before anything is made, so a setup refused part way is
	// undone as far as it got.
	t.Cleanup(func() {
		clean := context.WithoutCancel(ctx)
		for _, stmt := range []string{
			`DROP TABLE IF EXISTS "` + probe + `"`,
			`DROP SCHEMA IF EXISTS "` + role + `" CASCADE`,
			`REVOKE ALL ON SCHEMA "public" FROM "` + role + `"`,
			`REVOKE ALL ON DATABASE ` + quoted + ` FROM "` + role + `"`,
			`DROP ROLE IF EXISTS "` + role + `"`,
		} {
			_, _ = owner.ExecContext(clean, stmt)
		}
	})
	for _, stmt := range []string{
		`CREATE TABLE "` + probe + `" ("id" INTEGER)`,
		`CREATE ROLE "` + role + `" LOGIN PASSWORD 'probe'`,
		`GRANT CONNECT ON DATABASE ` + quoted + ` TO "` + role + `"`,
		`GRANT USAGE ON SCHEMA "public" TO "` + role + `"`,
		// A schema of the role's own, which the default search path puts
		// ahead of public, so its current schema is not the one the table
		// is in. The migration library's unqualified reference still
		// resolves to public, and so does the probe.
		`CREATE SCHEMA "` + role + `" AUTHORIZATION "` + role + `"`,
	} {
		if _, err := owner.ExecContext(ctx, stmt); err != nil {
			t.Skipf("this server will not let the test arrange a restricted role (%v)", err)
		}
	}

	// The role may reach the database and read the catalog, and may not read
	// the table. That is exactly the arrangement being described. The same
	// address as the owner's, whoever the owner is, signed in as the role.
	as, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	as.User = url.UserPassword(role, "probe")
	restricted := open(t, as.String())
	var probed int
	readErr := restricted.QueryRowContext(ctx,
		`SELECT 1 FROM "`+probe+`" LIMIT 1`).Scan(&probed)
	if readErr == nil {
		t.Skip("the restricted role can read the table, so there is nothing to tell apart")
	}

	// The catalog still answers, and answers the question that was asked.
	// This is why PostgreSQL is asked through pg_class: the information schema
	// is filtered by privilege, so a role with no rights on the table does not
	// see the table there either, and gives back the same conflation.
	query, err := catalogQuery(restricted.Server.Engine)
	if err != nil {
		t.Fatal(err)
	}
	var current string
	if err := restricted.QueryRowContext(ctx, `SELECT CURRENT_SCHEMA()`).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current != role {
		t.Errorf("the role's current schema is %q, so the arrangement under test is not the one made", current)
	}
	var seen int
	if err := restricted.QueryRowContext(ctx, query, probe).Scan(&seen); err != nil {
		t.Fatalf("a credential that may not read a table, with a schema of its own, could not see it in the catalog: %v", err)
	}

	// And the information schema is what that would have looked like.
	var filtered int
	if err := restricted.QueryRowContext(ctx,
		`SELECT 1 FROM "information_schema"."tables"
		 WHERE "table_schema" = 'public' AND "table_name" = ?`, probe).Scan(&filtered); err == nil {
		t.Error("the information schema is not privilege-filtered here, so the reason for pg_class no longer holds")
	}
	t.Logf("unreadable by this role (%v), present in pg_class, absent from the information schema", readErr)
}

// servers is each server engine a run may reach, with its address.
//
// This is an internal test of the migrate package and dbtest depends on
// migrate, so the narrowing comes from the package below both rather than
// from a second copy of the parsing here.
func servers(t *testing.T, each func(t *testing.T, engine database.Engine, address string)) {
	for engine, env := range map[database.Engine]string{
		database.Postgres: postgresURLEnv,
		database.MySQL:    mysqlURLEnv,
		database.MariaDB:  mariadbURLEnv,
	} {
		t.Run(string(engine), func(t *testing.T) {
			engines.SkipUnless(t, engine)
			address := os.Getenv(env)
			if address == "" {
				t.Skipf("%s is not set", env)
			}
			each(t, engine, address)
		})
	}
}

// The lease is renewed on one pooled connection while the migration runs on
// another, so a pool of one is refused in words. Allowed, a long statement
// would hold every renewal back and the holder would stop part way.
func TestAPoolOfOneIsRefusedRatherThanWaitedOn(t *testing.T) {
	servers(t, func(t *testing.T, _ database.Engine, address string) {
		target, err := database.ParseURL(address)
		if err != nil {
			t.Fatal(err)
		}
		pool := database.DefaultPool()
		pool.MaxOpen, pool.MaxIdle = 1, 1
		db, err := database.OpenWithPool(t.Context(), target, pool)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })

		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		err = withLock(ctx, db, slog.Default(), func(context.Context, *held) error { return nil })
		if err == nil {
			t.Fatal("a pool of one connection was accepted for a migration")
		}
		if errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), dbMaxOpen) {
			t.Errorf("the refusal does not name the setting that fixes it: %v", err)
		}
	})
}

// What a failed upgrade tells an operator depends on what it leaves behind:
// nothing for an empty database, and a part-changed schema only on the two
// engines that change a schema outside a transaction.
func TestAFailedUpgradeNamesTheRecoveryItsEngineNeeds(t *testing.T) {
	cause := errors.New("no such table")
	for _, c := range []struct {
		engine  database.Engine
		before  int64
		backup  bool
		recover bool
	}{
		{database.Postgres, 0, false, false},
		{database.MySQL, 0, false, false},
		{database.Postgres, 38, false, true},
		{database.SQLite, 12, false, true},
		{database.MySQL, 38, true, true},
		{database.MariaDB, 3, true, true},
	} {
		err := upFailed(c.engine, c.before, cause)
		if !errors.Is(err, cause) {
			t.Errorf("%s from %d: the cause is lost: %v", c.engine, c.before, err)
		}
		if got := strings.Contains(err.Error(), "restore the backup"); got != c.backup {
			t.Errorf("%s from %d: names the backup = %v, want %v: %v", c.engine, c.before, got, c.backup, err)
		}
		if got := strings.Contains(err.Error(), "recreated"); got != c.recover {
			t.Errorf("%s from %d: names recreating = %v, want %v: %v", c.engine, c.before, got, c.recover, err)
		}
	}
}

// An upgrade its caller stopped part way is reported as stopped, with no
// recovery named: the next start applies the schema again on every engine. A
// failure with its caller still waiting names the recovery as above.
func TestAStoppedUpgradeNamesNoRecovery(t *testing.T) {
	cause := errors.New("context canceled")
	stopped, cancel := context.WithCancel(t.Context())
	cancel()
	for _, engine := range []database.Engine{database.MySQL, database.MariaDB, database.Postgres} {
		err := upEnded(stopped, engine, 43, cause)
		if !errors.Is(err, cause) || !strings.Contains(err.Error(), "stopped part way") ||
			strings.Contains(err.Error(), "restore the backup") || strings.Contains(err.Error(), "recreated") {
			t.Errorf("%s: a stopped upgrade answered %v", engine, err)
		}
	}
	if err := upEnded(t.Context(), database.MySQL, 43, cause); !strings.Contains(err.Error(), "restore the backup") {
		t.Errorf("a failed upgrade with its caller waiting answered %v", err)
	}
}

func TestSQLiteMigratesOnOneConnectionAndGetsItsPoolBack(t *testing.T) {
	// A migration's connection settings have to reach the transaction it
	// opens, which on a wider pool they need not.
	target, err := database.ParseURL("sqlite://" + t.TempDir() + "/pool.db")
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.OpenWithPool(t.Context(), target, database.DefaultPool())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	width := db.Stats().MaxOpenConnections
	if width < 2 {
		t.Fatalf("a deployment's SQLite pool is %d wide, which proves nothing here", width)
	}

	quiet := slog.New(slog.DiscardHandler)
	var during int
	if err := withLock(t.Context(), db, quiet, func(context.Context, *held) error {
		during = db.Stats().MaxOpenConnections
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if during != 1 {
		t.Errorf("SQLite migrated on a pool of %d connections, want 1", during)
	}
	if after := db.Stats().MaxOpenConnections; after != width {
		t.Errorf("the pool was %d wide after migrating, want %d as before", after, width)
	}

	// The idle limit is not reported, so it is read from what the pool keeps:
	// connections held at once and then returned stay open up to it.
	const held = 4
	conns := make([]*sql.Conn, 0, held)
	for range held {
		conn, err := db.DB.DB.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	if idle := db.Stats().Idle; idle != held {
		t.Errorf("%d of %d returned connections stayed open after migrating, want all of them", idle, held)
	}
}
