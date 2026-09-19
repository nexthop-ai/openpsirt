package database_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

func TestLosingARaceIsWorthRetryingAndAMistakeIsNot(t *testing.T) {
	// The distinction the whole retry rests on. A conflict wrongly called
	// permanent surfaces as an error somebody reads; a mistake wrongly
	// retried surfaces as a deployment hammering its database and hanging.
	//
	// The clustered case is the one that motivated this: a cluster certifies a
	// write at COMMIT, and reports the failure as a deadlock — on a
	// transaction whose every statement had already succeeded.
	worth := []error{
		&mysql.MySQLError{Number: 1213, Message: "Deadlock found when trying to get lock"},
		&mysql.MySQLError{Number: 1205, Message: "Lock wait timeout exceeded"},
		&mysql.MySQLError{Number: 1180, Message: "Got error during COMMIT"},
		&pgconn.PgError{Code: "40001", Message: "could not serialize access"},
		&pgconn.PgError{Code: "40P01", Message: "deadlock detected"},
		errors.New("database is locked (5) (SQLITE_BUSY)"),
	}
	for _, err := range worth {
		if !database.WorthRetrying(err) {
			t.Errorf("not retried: %v", err)
		}
	}

	// Everything else is somebody's mistake, and going again will not fix it.
	notWorth := []error{
		nil,
		errors.New("some other trouble"),
		&mysql.MySQLError{Number: 1062, Message: "Duplicate entry"},
		&mysql.MySQLError{Number: 1452, Message: "Cannot add or update a child row"},
		&pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"},
		&pgconn.PgError{Code: "23503", Message: "violates foreign key constraint"},
		&pgconn.PgError{Code: "42P01", Message: "relation does not exist"},
	}
	for _, err := range notWorth {
		if database.WorthRetrying(err) {
			t.Errorf("retried something that will never come out differently: %v", err)
		}
	}
}

func TestAWrappedFailureIsStillRecognized(t *testing.T) {
	// Every store wraps what the driver returned, so a check that only matched
	// a bare error would recognize none of them.
	wrapped := errors.Join(
		errors.New("record this sign-in"),
		&mysql.MySQLError{Number: 1213, Message: "Deadlock found"},
	)
	if !database.WorthRetrying(wrapped) {
		t.Error("a wrapped deadlock was not recognized")
	}
}

func TestARetriedTransactionLeavesNothingBehindFromTheAttemptThatFailed(t *testing.T) {
	// The property the retry rule rests on and the reason nothing a
	// transaction depends on may be read outside it: a retry re-runs the
	// closure against a database where the failed attempt never happened.
	//
	// Getting this wrong is invisible in the ordinary case, because most
	// closures write the same rows every time. It shows up when one appends.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		if _, err := db.NewRaw(`CREATE TABLE "retried" ("id" INTEGER PRIMARY KEY, "note" VARCHAR(16))`).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.NewRaw(`DROP TABLE "retried"`).Exec(context.WithoutCancel(ctx))
		})

		attempts := 0
		err := database.InTransaction(ctx, db.DB, func(ctx context.Context, tx bun.Tx) error {
			attempts++
			if _, err := tx.NewRaw(`INSERT INTO "retried" ("id", "note") VALUES (?, ?)`,
				attempts, "written").Exec(ctx); err != nil {
				return err
			}
			if attempts == 1 {
				// A cluster's report at COMMIT, on a transaction whose
				// every statement had already succeeded.
				return &mysql.MySQLError{Number: 1213, Message: "Deadlock found"}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("a transaction that lost one race did not go again: %v", err)
		}
		if attempts != 2 {
			t.Errorf("ran %d times, want a second attempt after the first lost", attempts)
		}

		var rows []struct {
			ID int64 `bun:"id"`
		}
		if err := db.NewRaw(`SELECT "id" FROM "retried"`).Scan(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].ID != 2 {
			t.Errorf("the failed attempt left %d rows behind: %+v", len(rows), rows)
		}
	})
}

func TestAMistakeIsReportedWithoutGoingAgain(t *testing.T) {
	// Retrying what will never come out differently is how a deployment
	// hammers its database and hangs, so the closure runs once and the failure
	// is handed back as it was.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		mistake := errors.New("a column that does not exist")
		attempts := 0
		err := database.InTransaction(t.Context(), db.DB,
			func(ctx context.Context, tx bun.Tx) error {
				attempts++
				return mistake
			})
		if !errors.Is(err, mistake) {
			t.Errorf("the failure came back as %v, losing what it was", err)
		}
		if attempts != 1 {
			t.Errorf("ran %d times for a failure going again cannot fix", attempts)
		}
	})
}

func TestContentionThatNeverClearsIsReportedRatherThanRetriedForever(t *testing.T) {
	// Contention surviving every attempt is not contention: it is two writers
	// permanently fighting over the same rows, and going again forever turns
	// a design problem into an outage with no error in it.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		attempts := 0
		err := database.InTransaction(t.Context(), db.DB,
			func(ctx context.Context, tx bun.Tx) error {
				attempts++
				return &pgconn.PgError{Code: "40001", Message: "could not serialize access"}
			})
		if err == nil {
			t.Fatal("a transaction that never succeeded reported success")
		}
		if attempts != database.Attempts {
			t.Errorf("tried %d times, want %d", attempts, database.Attempts)
		}
		// And what it gave up on is still readable, because "gave up" without
		// saying what went wrong is not a report anybody can act on.
		if !strings.Contains(err.Error(), "serialize") {
			t.Errorf("what it gave up on was lost: %v", err)
		}
	})
}

func TestGivingUpDoesNotWaitToBackOffBeforeNothing(t *testing.T) {
	// The backoff sat inside the loop body with nothing guarding the last
	// attempt, so a transaction that had already run out of attempts slept a
	// final interval before returning an error that was decided before it
	// began — holding the handler goroutine and its pooled connection for it,
	// under exactly the sustained contention this path exists to report.
	//
	// Measured from the last attempt rather than from the start, because the
	// backoffs between attempts are jittered and their totals overlap: a run
	// with the final sleep and a run without it can take the same wall-clock
	// time. What cannot overlap is what happens after the last attempt
	// returns, which is a rollback and nothing else.
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		var lastAttempt time.Time
		err := database.InTransaction(t.Context(), db.DB,
			func(ctx context.Context, tx bun.Tx) error {
				defer func() { lastAttempt = time.Now() }()
				return &pgconn.PgError{Code: "40001", Message: "could not serialize access"}
			})
		trailing := time.Since(lastAttempt)
		if err == nil {
			t.Fatal("a transaction that never succeeded reported success")
		}
		// The shortest final backoff is the fifth step, 50ms before any
		// jitter. Anything under half of that is the rollback and the return.
		if trailing > 25*time.Millisecond {
			t.Errorf("giving up spent %s after its last attempt, which is a backoff before nothing", trailing)
		}
	})
}

func TestFindingNothingIsToldApartFromFailing(t *testing.T) {
	// This was three separate copies, each asking whether the words "no rows"
	// appeared anywhere in the message. That is wrong in both directions, and
	// both mistakes are silent: an unrelated failure mentioning the phrase
	// reads as an empty result, and a driver wording it differently reads as a
	// failure. "Not found" decides control flow in enough places here that
	// either one changes behavior rather than logging.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		if _, err := db.NewRaw(`CREATE TABLE "nothing_here" ("id" INTEGER PRIMARY KEY)`).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.NewRaw(`DROP TABLE "nothing_here"`).Exec(context.WithoutCancel(ctx))
		})

		var id int64
		err := db.NewRaw(`SELECT "id" FROM "nothing_here" WHERE "id" = 1`).Scan(ctx, &id)
		if !database.IsNoRows(err) {
			t.Errorf("a query that found nothing reads as %v", err)
		}

		// A failure that talks about rows is still a failure.
		for _, impostor := range []error{
			errors.New("could not delete: no rows may be removed while a scan is open"),
			errors.New("no rows"),
		} {
			if database.IsNoRows(impostor) {
				t.Errorf("a failure read as an empty result: %v", impostor)
			}
		}
	})
}

func TestWithinOpensATransactionForThisPackagesOwnHandle(t *testing.T) {
	// The handle this package hands out embeds a bun.DB rather than being
	// one, so an assertion for *bun.DB alone was failed by the very handle
	// Open returns — and the arm that answered it ran each statement as its
	// own autocommit, with no transaction, no retry and nothing said. The two
	// spellings differ by four characters and both compile.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		for _, handle := range []struct {
			what string
			db   bun.IDB
		}{
			{"this package's handle", db},
			{"the embedded handle", db.DB},
		} {
			t.Run(handle.what, func(t *testing.T) {
				var inside bun.IDB
				if err := database.Within(t.Context(), handle.db,
					func(ctx context.Context, tx bun.IDB) error {
						inside = tx
						return nil
					}); err != nil {
					t.Fatalf("Within: %v", err)
				}
				if _, ok := inside.(bun.Tx); !ok {
					t.Errorf("the closure ran against %T, which is not a transaction", inside)
				}
			})
		}
	})
}

func TestWithinJoinsATransactionItIsGiven(t *testing.T) {
	// The case the helper is named for: a method whose requirement is "both
	// statements or neither" has that met by the caller's transaction, and
	// refusing would make it uncallable from inside one.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		err := database.InTransaction(t.Context(), db.DB, func(ctx context.Context, tx bun.Tx) error {
			return database.Within(ctx, tx, func(ctx context.Context, inner bun.IDB) error {
				if inner != bun.IDB(tx) {
					t.Errorf("the caller's transaction was replaced by %T", inner)
				}
				return nil
			})
		})
		if err != nil {
			t.Fatalf("Within inside a transaction: %v", err)
		}
	})
}

func TestWithinRefusesAHandleItDoesNotRecognize(t *testing.T) {
	// The arm that used to run the closure unwrapped. A handle nothing here
	// knows about is a fault worth reporting, not a fifth way to run work
	// outside a transaction and say nothing about it.
	err := database.Within(t.Context(), stranger{}, func(ctx context.Context, db bun.IDB) error {
		t.Error("the closure ran against a handle that is not a transaction")
		return nil
	})
	if err == nil {
		t.Fatal("an unrecognized handle was accepted")
	}
	if !strings.Contains(err.Error(), "stranger") {
		t.Errorf("the refusal does not say what it was given: %v", err)
	}
}

// stranger satisfies bun.IDB and is nothing Within knows about.
type stranger struct{ bun.IDB }

// mute is a result that cannot say how many rows a write matched, which is
// what a driver upgrade, a proxy or a fifth engine could start doing at any
// time. No driver here does it today, which is exactly why nothing would
// notice the day one starts.
type mute struct{}

func (mute) LastInsertId() (int64, error) { return 0, errors.New("no identifier to give") }
func (mute) RowsAffected() (int64, error) { return 0, errors.New("this driver cannot count matches") }

func TestACountThatCannotBeReadIsAFaultRatherThanZero(t *testing.T) {
	// "The row was not there" and "I could not tell you" are different
	// answers, and the callers act on the first: a conditional update reads
	// the count back to find out whether the row it read is still the row it
	// is writing. Discarding the error spells every one of those as a
	// confident sentence about rows nobody counted — a job given up while
	// still held, a delete that committed answered as a 404, a claim nobody
	// ever takes.
	n, err := database.Affected(mute{})
	if err == nil {
		t.Fatalf("a count that could not be read came back as %d", n)
	}
	if n != 0 {
		t.Errorf("a failed read reported %d rows", n)
	}
	// And it says what went wrong, because "0" tells an operator nothing.
	if !strings.Contains(err.Error(), "cannot count matches") {
		t.Errorf("what the driver said was lost: %v", err)
	}
}

func TestACountThatCanBeReadIsReturned(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		if _, err := db.NewRaw(`CREATE TABLE "counted" ("id" INTEGER PRIMARY KEY)`).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.NewRaw(`DROP TABLE "counted"`).Exec(context.WithoutCancel(ctx))
		})
		res, err := db.NewRaw(`INSERT INTO "counted" ("id") VALUES (1), (2), (3)`).Exec(ctx)
		if err != nil {
			t.Fatal(err)
		}
		n, err := database.Affected(res)
		if err != nil {
			t.Fatalf("Affected: %v", err)
		}
		if n != 3 {
			t.Errorf("three rows were written and the count says %d", n)
		}
	})
}
