package database_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/nexthop-ai/openpsirt/internal/database"

	_ "modernc.org/sqlite" // the driver whose error type this pins
)

func TestAnEngineFailureIsToldFromSomebodyAskingTheImpossible(t *testing.T) {
	// The distinction an API handler needs and had no way to ask for. A store
	// answers both kinds through one return, and thirty handlers turned both
	// into a 422 with the message in it — so a lost connection reached
	// whoever asked as a bad request carrying the statement text and the
	// address the driver had tried.
	for _, c := range []struct {
		what   string
		err    error
		engine bool
	}{
		{"a MySQL error", &mysql.MySQLError{Number: 1213, Message: "deadlock"}, true},
		{"a PostgreSQL error", &pgconn.PgError{Code: "42803"}, true},
		{"a wrapped driver error",
			fmt.Errorf("read what is open there: %w", &pgconn.PgError{Code: "08006"}), true},
		{"no rows where one was required", sql.ErrNoRows, true},
		{"a connection the pool could not use", driver.ErrBadConn, true},
		{"a connection already finished with", sql.ErrConnDone, true},
		{"a transaction already finished with", sql.ErrTxDone, true},
		{"a query that outlived its deadline", context.DeadlineExceeded, true},
		// A caller that goes away mid-query is not a caller asking for
		// something impossible, and answering it as one puts the statement
		// text in a 422 and logs nothing.
		{"a query whose caller went away", context.Canceled, true},

		{"nothing at all", nil, false},
		{"a sentence a store wrote",
			errors.New("a decision already stands here"), false},
		// Read from the driver's own types rather than from the message, so a
		// store's sentence that happens to contain a driver's vocabulary is
		// still a sentence.
		{"a sentence that sounds like a driver",
			errors.New("that would be a duplicate key for this deadlock of a release"), false},
	} {
		t.Run(c.what, func(t *testing.T) {
			if got := database.FromEngine(c.err); got != c.engine {
				t.Errorf("%s reads as engine=%v, want %v", c.what, got, c.engine)
			}
		})
	}
}

func TestASQLiteFaultIsAnEngineFailureLikeAnyOther(t *testing.T) {
	// This listed two driver error types and called the third absent, so on
	// the engine the quick loop actually runs, a constraint violation, a
	// missing column and a full disk were all answered as the caller's
	// mistake — with the driver's own text in the body, and nothing logged
	// because the arm that logs was never reached.
	//
	// The errors are taken from the driver rather than constructed, because
	// what is being pinned is that the driver still produces the type this
	// matches. A dependency bump that changed it would pass any test that
	// built its own.
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := t.Context()
	for _, setup := range []string{
		`CREATE TABLE "t" ("a" TEXT PRIMARY KEY, "b" TEXT NOT NULL)`,
		`INSERT INTO "t" ("a", "b") VALUES ('x', 'y')`,
	} {
		if _, err := db.ExecContext(ctx, setup); err != nil {
			t.Fatalf("%s: %v", setup, err)
		}
	}

	for _, c := range []struct{ what, statement string }{
		{"a unique constraint", `INSERT INTO "t" ("a", "b") VALUES ('x', 'z')`},
		{"a not-null constraint", `INSERT INTO "t" ("a", "b") VALUES ('q', NULL)`},
		// Qualified, because SQLite falls back to reading a double-quoted
		// name it cannot resolve as a string literal, and an unqualified one
		// would be accepted rather than refused.
		{"a column the schema does not have", `SELECT "t"."nope" FROM "t"`},
		{"a table the schema does not have", `SELECT * FROM "nope"`},
	} {
		t.Run(c.what, func(t *testing.T) {
			_, err := db.ExecContext(ctx, c.statement)
			if err == nil {
				t.Fatalf("%s was accepted", c.statement)
			}
			if !database.FromEngine(err) {
				t.Errorf("%s reads as the caller asking for something impossible: %v", c.what, err)
			}
		})
	}

	// And a store's own sentence is still a sentence on this engine too.
	if database.FromEngine(errors.New("a decision already stands here")) {
		t.Error("a sentence a store wrote reads as an engine failure")
	}
}

func TestAStoreSentenceWrappingADriverFailureReadsAsTheFailure(t *testing.T) {
	// The precedence, stated once. A store that wraps what the engine said
	// keeps the engine's error in the chain, and the handler above needs to
	// know the database is broken rather than render the store's sentence
	// with a 422 — the wrapping is context, not a reclassification.
	wrapped := fmt.Errorf("record this decision: %w", &pgconn.PgError{Code: "08006"})
	if !database.FromEngine(wrapped) {
		t.Errorf("a store sentence wrapping a driver failure hid it: %v", wrapped)
	}
}
