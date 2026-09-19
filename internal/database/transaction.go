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
	"modernc.org/sqlite"
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
// Everything fn depends on must be read inside fn. A retry re-runs the
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
		// Nothing follows the last attempt, so there is nothing to back off
		// before. Sleeping here held the handler goroutine and its pooled
		// connection for a further backoff interval before returning an error
		// already decided — under exactly the sustained contention this path
		// exists to report.
		if attempt == Attempts {
			break
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

// ErrGoAgain is a store saying it lost a race that a fresh transaction can win.
//
// The engines say this for themselves, in the codes below. This is for the
// condition a query expresses rather than one an engine reports: a conditional
// update that matched nothing because another writer moved the row between the
// read and the write.
//
// A store that owns its transaction takes that again itself. One handed
// somebody else's cannot — the statement that failed has already poisoned the
// transaction on one engine, and half the act belongs to the caller — so it
// says so and the caller's helper re-runs the whole of it.
var ErrGoAgain = errors.New("lost a race with another writer")

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
	if errors.Is(err, ErrGoAgain) {
		return true
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

	// SQLite. A single-file database contends differently: a writer that
	// arrives while another holds the file is told the database is busy or
	// locked. The driver carries the result code, and the low byte of an
	// extended code is the primary one — a busy connection reports several
	// different extended codes for the same condition.
	var lite *sqlite.Error
	if errors.As(err, &lite) {
		switch lite.Code() & 0xff {
		case 5, // SQLITE_BUSY: another connection holds the file
			6: // SQLITE_LOCKED: another connection holds a table within it
			return true
		}
		return false
	}

	// And by text for an error that has crossed a boundary as a sentence, so
	// a driver's own wording still reads as contention where the type did not
	// survive.
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

// FromRead says which of two things a failed read was: a row that is not
// there, or a read that could not be made.
//
// absent is what the caller should get where the row is genuinely missing —
// the asking package's own sentinel, worded however that package words it.
// reading names the act, for the line an operator reads: "look up product 12".
//
// One spelling, because the difference is a status code at every caller and
// made by hand it is made differently. A reader wrapping every failure alike
// answers "that does not exist" for a database it could not reach, and every
// caller above it repeats that to whoever asked — so an outage tells an
// authenticated reader their products, builds and findings are gone.
func FromRead(err error, absent error, reading string) error {
	if IsNoRows(err) {
		return absent
	}
	return fmt.Errorf("%s: %w", reading, err)
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
// The rule about reads is unchanged, and it reaches further here: fn may
// be re-run by a retry it cannot see, so everything it depends on is read
// inside it.
// Each handle it may be given is named. This package's own handle embeds
// `*bun.DB` rather than being one, so a type assertion for `*bun.DB` alone is
// failed by the very handle Open returns — and a fallthrough answering that by
// running each statement as its own autocommit is no transaction, no retry and
// nothing said, while the two spellings differ by four characters and both
// compile. Anything this does not recognize is a fault rather than a fifth
// silent path.
func Within(ctx context.Context, db bun.IDB, fn func(context.Context, bun.IDB) error) error {
	join := func(ctx context.Context, tx bun.Tx) error { return fn(ctx, tx) }
	switch handle := db.(type) {
	case *DB:
		return InTransaction(ctx, handle.DB, join)
	case *bun.DB:
		return InTransaction(ctx, handle, join)
	case bun.Tx:
		// Already inside one, which is the case this helper is named for.
		return fn(ctx, handle)
	default:
		return fmt.Errorf("within a transaction: %T is neither a database handle nor a transaction", db)
	}
}

// Handle returns the pooled handle behind db, and false when db is a
// transaction.
//
// The same two spellings Within names, for the callers that need the handle
// rather than a closure: a store deciding whether it may open a transaction of
// its own. This package's handle embeds a *bun.DB rather than being one, so an
// assertion for *bun.DB alone is failed by the very handle Open returns — it
// compiles, and the store then refuses every write as though it were already
// inside somebody's transaction.
func Handle(db bun.IDB) (*bun.DB, bool) {
	switch handle := db.(type) {
	case *DB:
		return handle.DB, true
	case *bun.DB:
		return handle, true
	}
	return nil, false
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
// one. All three drivers have such a type, SQLite included: this listed two
// and called the third one absent, so on the engine the quick loop actually
// runs, a constraint violation, a missing column and a full disk were all
// answered as the caller's mistake, with the driver's own text in the body and
// nothing logged.
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
	var lite *sqlite.Error
	if errors.As(err, &lite) {
		return true
	}
	// Not a driver's own type, but only ever produced by one: a statement that
	// ran and returned nothing where something was required, a pool or a
	// transaction that was already finished with, and a query that stopped
	// because the caller's context did — whether it ran out of time or the
	// caller went away.
	return errors.Is(err, sql.ErrNoRows) ||
		errors.Is(err, driver.ErrBadConn) ||
		errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, sql.ErrTxDone) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled)
}

// Affected reports how many rows a write matched.
//
// An engine that cannot say is a fault, not a zero. "The row was not there"
// and "I could not tell you" are different answers, and the callers of this
// act on the first one: a conditional update reads the count back to find out
// whether the row it read is still the row it is writing, so a count read as
// zero becomes "somebody got there first", "you no longer hold this job" or a
// 404 for a delete that committed. Discarding the error spells every one of
// those as a confident sentence about rows nobody counted.
//
// What the count means is settled elsewhere and is the same on all four
// engines: rows *matched*, not rows changed — see the connection settings in
// this package, and `DESIGN-database.md`.
//
// No current driver returns an error here, which is the reason this is worth
// a helper rather than a rule people remember. Nothing would fail today if a
// caller got it wrong, and nothing will report it on the day one starts.
func Affected(res sql.Result) (int64, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read how many rows were matched: %w", err)
	}
	return n, nil
}
