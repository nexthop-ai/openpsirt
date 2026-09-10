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
		{"a query that outlived its deadline", context.DeadlineExceeded, true},

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
