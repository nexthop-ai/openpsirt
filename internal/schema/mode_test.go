// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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

func TestStandardQuotingSurvivesAlongsideStrictness(t *testing.T) {
	// Both at once: the quoting is asked for by appending to the mode, and
	// appending is only correct if what was already there is still in force.
	// Setting a mode replaces it rather than adding to it, and what it would
	// replace includes the rule that refuses a value too long for its column —
	// a nine character string into a four character column, back four
	// characters long with no error, on two engines and not the other two.
	// Silent truncation is the worst shape a portability difference takes:
	// nothing fails, and the data is wrong.
	//
	// The two meet on one column, or this cannot fail for the reason it is
	// named: a reserved word carrying a width is one column that both halves
	// have to be in force for. The CREATE fails without the quoting, and the
	// write below is wrong without the strictness.
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
