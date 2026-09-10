package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"
)

// Attempts is how many times a transaction is tried before its failure is
// reported.
//
// Contention that survives this many tries is not contention: it is a design
// that has two writers permanently fighting over the same rows, and retrying
// forever would turn that into a hang rather than a report.
const Attempts = 5

// InTransaction runs fn inside a transaction and retries the whole of it if
// the database refuses the write for a reason that going again can fix.
//
// **Everything fn depends on must be read inside fn.** A retry re-runs the
// closure from the beginning against a database that has moved, so a value
// read before the transaction started, or carried over from a previous
// attempt, describes a world that no longer exists — and writing a decision
// made from it is worse than the conflict that forced the retry, because
// nothing reports it. This is the rule a reviewer should check first.
//
// Retrying matters more than it looks. A clustered deployment certifies a
// write when it commits, not when the statement runs, so two nodes that
// touched the same rows find out at COMMIT and the loser is told its whole
// transaction was rolled back. Code that guards each statement and trusts the
// commit sees none of this: the statements all succeeded.
func InTransaction(ctx context.Context, db *bun.DB, fn func(context.Context, bun.Tx) error) error {
	var err error
	for attempt := 1; attempt <= Attempts; attempt++ {
		err = db.RunInTx(ctx, nil, fn)
		if err == nil {
			return nil
		}
		if !WorthRetrying(err) {
			return err
		}
		if ctx.Err() != nil {
			return err
		}
		// Backing off with a little randomness, so two writers that collided
		// do not line up and collide again on the same schedule.
		select {
		case <-ctx.Done():
			return err
		case <-time.After(backoff(attempt)):
		}
	}
	return fmt.Errorf("gave up after %d attempts: %w", Attempts, err)
}

// WorthRetrying reports whether a failure is one that going again can fix.
//
// This is the one place besides the migrations and the queue's locking that
// knows which engine it is talking to, and it has to be: what each of them
// calls "you lost a race, try again" is a different code, and treating an
// unrecognized failure as retryable would hammer a database over a constraint
// violation that will never come out differently.
//
// So the list is of what is known to be worth retrying, and everything else is
// reported. A conflict wrongly treated as permanent surfaces as an error
// somebody sees; a permanent error wrongly retried surfaces as a deployment
// that hangs under load.
func WorthRetrying(err error) bool {
	if err == nil {
		return false
	}

	// MySQL and MariaDB. A cluster reports a certification failure at commit
	// as a deadlock, which is why this matters on a write that appeared to
	// have succeeded statement by statement.
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		switch my.Number {
		case 1213, // deadlock found, and what a cluster says when it could not certify
			1205, // lock wait timeout
			1180: // an error during commit, which is how some cluster failures arrive
			return true
		}
		return false
	}

	// PostgreSQL.
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "40001", // serialization failure
			"40P01": // deadlock detected
			return true
		}
		return false
	}

	// SQLite has no error type worth matching on through this driver, and a
	// single-file database contends differently anyway: a writer that arrives
	// while another holds the file is told the database is busy or locked.
	text := strings.ToLower(err.Error())
	for _, known := range []string{"database is locked", "database table is locked", "sqlite_busy"} {
		if strings.Contains(text, known) {
			return true
		}
	}
	return false
}

// backoff is how long to wait before trying again.
//
// Growing with each attempt, and jittered, so that two writers which collided
// do not line up and collide again on the same schedule. The randomness is for
// spreading load and decides nothing, which is why an ordinary generator is
// right here — a cryptographic one would be slower and no better at it.
func backoff(attempt int) time.Duration {
	step := time.Duration(attempt) * 10 * time.Millisecond
	//nolint:gosec // G404: this spreads retries apart; nothing is kept secret by it.
	return step + time.Duration(rand.N(int64(step)+1))
}

// IsNoRows reports whether a query found nothing.
//
// One place, because there were three, and all three matched on the words "no
// rows" appearing somewhere in the message. That is wrong in both directions:
// an unrelated failure whose message happens to contain the phrase reads as an
// empty result, and a driver wording it differently reads as a failure. Both
// mistakes are silent, and "not found" is a control-flow answer in enough
// places here that getting it wrong changes behavior rather than logging.
//
// The comparison is against the standard sentinel, through the wrapping, which
// is what every driver here actually returns.
func IsNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

// IsDuplicate reports whether a write was refused by a unique constraint.
//
// Here rather than at a call site for the same reason WorthRetrying is: what
// each engine calls "that already exists" is a different code in a different
// error type, and spreading that around would make no engine-specific SQL in
// the core meaningless one helper at a time.
//
// It exists so a rule the database enforces can be *explained* by the code. A
// unique index is the right place to enforce "only one of these", because two
// writers arriving together both walk through any check made before the write
// — but "duplicate key value violates constraint decision_live_unique" is not
// a sentence anybody should be shown.
func IsDuplicate(err error) bool {
	if err == nil {
		return false
	}

	// 1062 is a duplicate entry; 1586 is the same thing reported against a
	// partitioned table.
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1062 || my.Number == 1586
	}

	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23505"
	}

	// SQLite reports it as text, the same way it reports a busy database.
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// Within runs fn in a transaction, or in the caller's if this handle is
// already one.
//
// A store built over a transaction is a store somebody else has already put
// inside one. Refusing there is the right answer for a method that has to own
// the retry boundary — it decides what a retry re-reads, and it cannot decide
// that from inside a transaction it does not control. But a method whose
// requirement is only "both statements or neither" has that requirement met by
// the caller's transaction, and refusing makes it uncallable from inside one
// for no gain.
//
// Written twice by hand it read as a fallback to writing outside a transaction
// — the else-branch under a comment saying "both statements or neither" —
// which is what it looks like and not what it is. Named, it says which of the
// two it is doing.
//
// **The rule about reads is unchanged**, and it reaches further here: fn may
// be re-run by a retry it cannot see, so everything it depends on is read
// inside it.
func Within(ctx context.Context, db bun.IDB, fn func(context.Context, bun.IDB) error) error {
	if outermost, ok := db.(*bun.DB); ok {
		return InTransaction(ctx, outermost, func(ctx context.Context, tx bun.Tx) error {
			return fn(ctx, tx)
		})
	}
	return fn(ctx, db)
}

// FromEngine reports whether an error came from the database rather than from
// the caller having asked for something impossible.
//
// The distinction is what an API handler needs and had no way to ask for. A
// store answers two kinds of error through one return: "you may not do that
// here", which is a sentence somebody wrote for a person to read, and "the
// query failed", which carries the statement text and whatever the driver put
// in its message — for a connection failure, the address and the user it tried.
// A default arm that turned both into a 422 with the message in it answered a
// broken database as though the caller had mistyped, and handed them the
// inside of the deployment while doing it.
//
// It reads the driver's own types rather than the message, so a sentence a
// store wrote that happens to contain the word "duplicate" is not mistaken for
// one. SQLite has no error type worth matching on through this driver, which
// makes this conservative there — and conservative here means an engine
// failure read as a refusal, which is the direction the caller-facing message
// is already safe in, because a store's own sentences are the only thing that
// reaches it.
func FromEngine(err error) bool {
	if err == nil {
		return false
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return true
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return true
	}
	// Not a driver's own type, but only ever produced by one: a statement that
	// ran and returned nothing where something was required, a pool that could
	// not hand out a connection, and a query that outlived its deadline.
	return errors.Is(err, sql.ErrNoRows) ||
		errors.Is(err, driver.ErrBadConn) ||
		errors.Is(err, context.DeadlineExceeded)
}
