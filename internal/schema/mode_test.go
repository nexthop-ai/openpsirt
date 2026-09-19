package schema_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// truncation is what every server engine puts in the message when it refuses a
// value too long for its column.
//
// The SQLSTATE rather than the prose: PostgreSQL says "value too long for type
// character varying(4)" and the other two say "Data too long for column 'c' at
// row 1", and all three carry 22001 — the standard's own code for a string cut
// on the right. Matching the code rather than three wordings keeps this from
// needing an engine-specific arm in a test.
const truncation = "22001"

// refused reports whether an error is the engine refusing the value, and fails
// the test when it is anything else.
//
// A refusal is one of the two correct answers here, so the insert's error is an
// outcome rather than a failure — which is how a leftover table, a dropped
// connection or a typo in a later edit came to read as the engine doing its
// job. The test that pins no-silent-truncation observed nothing and passed.
func refused(t *testing.T, err error) bool {
	t.Helper()
	if err == nil {
		return false
	}
	if !strings.Contains(err.Error(), truncation) {
		t.Fatalf("the write failed for a reason that is not about the value: %v", err)
	}
	return true
}

func TestAnOversizedValueIsRefusedRatherThanTruncated(t *testing.T) {
	// A request to two of the engines for standard identifier quoting nearly cost
	// this the strictness that makes an oversized value an error. Setting a
	// mode replaces it rather than adding to it, and what it replaced included
	// the rule that refuses a value too long for its column — so a nine
	// character string went into a four character column and came back four
	// characters long, with no error, on two engines and not on the other two.
	//
	// Silent truncation is the worst shape a portability difference can take:
	// nothing fails, and the data is wrong. This is here so that the quoting
	// setting can never be written in a way that turns it off again.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := context.Background()
		probe := probeTable(t)
		if _, err := db.ExecContext(ctx,
			`CREATE TABLE "`+probe+`" ("c" VARCHAR(4))`); err != nil {
			t.Fatalf("create: %v", err)
		}
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DROP TABLE "`+probe+`"`) })

		const written = "123456789"
		_, err := db.ExecContext(ctx, `INSERT INTO "`+probe+`" ("c") VALUES (?)`, written)
		if refused(t, err) {
			return // Refused outright, which is one correct answer.
		}

		// The other correct answer is to store it whole — one engine does not
		// constrain a text column's width at all, which is documented
		// behavior and loses nothing. What must never happen is the third
		// outcome: accepted, changed, and no error.
		var stored string
		if err := db.QueryRowContext(ctx, `SELECT "c" FROM "`+probe+`"`).Scan(&stored); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if stored != written {
			t.Errorf("a value was accepted and silently changed: wrote %q, read %q", written, stored)
		}
	})
}

func TestStandardQuotingSurvivesAlongsideStrictness(t *testing.T) {
	// Both at once, because the fix for one is what broke the other: the
	// quoting is asked for by appending to the mode, and appending is only
	// correct if what was already there is still in force.
	//
	// The two have to meet on one column, or this cannot fail for the
	// reason it is named. It declared a reserved word and an ordinary integer,
	// wrote 1 and 2, and read 1 back — which passes with strictness entirely
	// off, leaving the conjunction pinned by nothing. A reserved word carrying
	// a width is one column that both halves have to be in force for: the
	// CREATE fails without the quoting, and the write below is wrong without
	// the strictness.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := context.Background()
		probe := probeTable(t)
		if _, err := db.ExecContext(ctx,
			`CREATE TABLE "`+probe+`" ("rank" BIGINT, "order" VARCHAR(4))`); err != nil {
			t.Fatalf("standard quoting is not in force: %v", err)
		}
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DROP TABLE "`+probe+`"`) })

		const written = "123456789"
		_, err := db.ExecContext(ctx,
			`INSERT INTO "`+probe+`" ("rank", "order") VALUES (1, ?)`, written)
		if refused(t, err) {
			return // Refused outright, which is one correct answer.
		}

		var rank int
		var stored string
		if err := db.QueryRowContext(ctx,
			`SELECT "rank", "order" FROM "`+probe+`"`).Scan(&rank, &stored); err != nil {
			t.Fatalf("select: %v", err)
		}
		if rank != 1 {
			t.Errorf("read %d", rank)
		}
		if stored != written {
			t.Errorf("a value in a reserved-word column was accepted and silently changed: wrote %q, read %q",
				written, stored)
		}
	})
}

func TestTheConnectionNamesBothModesItDependsOn(t *testing.T) {
	// The probes above observe the server's behavior, which is the right thing
	// to pin and is not the whole of it: they pass against a server that
	// happened to be configured correctly, whatever the connection asked for.
	// This says the modes are in force by name, so losing one is a failure
	// that names the mode rather than a value that came back a character
	// short.
	//
	// It cannot tell an asserted mode from an inherited one, and nothing
	// asked of a connection can: what the session holds is the union. What
	// catches a connection string that stops asking is the test over the
	// string itself, in internal/database — against the server these run on,
	// dropping the strictness from the DSN changes nothing observable here,
	// because that server holds it globally. Which is the whole reason the
	// mode is named rather than inherited.
	named := func(t *testing.T, db *database.DB) {
		var mode string
		if err := db.QueryRowContext(context.Background(),
			"SELECT @@SESSION.sql_mode").Scan(&mode); err != nil {
			t.Fatalf("read the session mode: %v", err)
		}
		for _, want := range []string{"ANSI_QUOTES", "STRICT_TRANS_TABLES"} {
			if !strings.Contains(mode, want) {
				t.Errorf("the connection does not hold %s: %q", want, mode)
			}
		}
	}
	dbtest.Only(t, database.MySQL, named)
	dbtest.Only(t, database.MariaDB, named)
}
