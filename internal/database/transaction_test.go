package database_test

import (
	"context"
	"errors"
	"strings"
	"testing"

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
				// What a cluster reports at COMMIT, on a transaction whose
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
