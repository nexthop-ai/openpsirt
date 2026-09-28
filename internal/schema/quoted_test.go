// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// bareAfter matches a keyword that is always followed by an identifier, and an
// identifier that is not quoted.
//
// A quoted name does not match, so a hit is by construction a bare one.
var bareAfter = regexp.MustCompile(`(?i)\b(TABLE|INDEX|CONSTRAINT|REFERENCES)\s+([A-Za-z_][A-Za-z0-9_]*)`)

// bareColumn matches an unquoted name where a column name belongs. The words
// excluded are the ones that open a table constraint, or continue the
// declaration above, rather than naming a column.
//
// Every name in the body, not only the one that opens a line. Requiring a
// line start and trailing whitespace read a table declaration, where each
// column is on its own line, and nothing else — an index body is
// `("kind", "at")` on one line, so an unquoted column there was matched by
// neither this nor bareAfter, which is precisely what the helper below says is
// covered.
var bareColumn = regexp.MustCompile(
	`(?i)(?:^|[(,])\s*(?:(CONSTRAINT|PRIMARY|UNIQUE|FOREIGN|CHECK|REFERENCES|ON|DEFAULT|NOT|NULL)\b|([A-Za-z_][A-Za-z0-9_]*)\s*(?:[\s,)]|$))`)

// onTable matches the table an index is built on, or a clause beginning ON.
// Only the first is an identifier, and Go's patterns have no lookahead, so the
// words that open the others are set aside in code.
var onTable = regexp.MustCompile(`(?i)\bON\s+([A-Za-z_][A-Za-z0-9_]*)`)

// notATable is what follows ON in a clause that names no table.
var notATable = map[string]bool{"DELETE": true, "UPDATE": true, "CONFLICT": true}

// bareIn is every identifier a statement writes bare, as the words that say
// where: the keyword before it, or the column it declares.
func bareIn(statement string) []string {
	bare := withoutComments(statement)
	var found []string
	for _, m := range bareAfter.FindAllStringSubmatch(bare, -1) {
		found = append(found, strings.ToUpper(m[1])+" "+m[2])
	}
	for _, m := range onTable.FindAllStringSubmatch(bare, -1) {
		if !notATable[strings.ToUpper(m[1])] {
			found = append(found, "ON "+m[1])
		}
	}
	for _, m := range bareColumn.FindAllStringSubmatch(body(bare), -1) {
		if m[2] != "" {
			found = append(found, "column "+m[2])
		}
	}
	return found
}

// Each shape a bare name takes is reported, and the quoted form of each is not.
func TestABareNameIsFoundWhereverTheSchemaWritesOne(t *testing.T) {
	for _, c := range []struct {
		statement string
		bare      bool
	}{
		{`CREATE TABLE finding ("a" INTEGER)`, true},
		{`CREATE TABLE "finding" (a INTEGER)`, true},
		{`CREATE INDEX "finding_idx" ON finding ("a")`, true},
		{`CREATE INDEX "finding_idx" ON "finding" (a)`, true},
		{`CREATE TABLE "finding" ("a" INTEGER REFERENCES product ("id") ON DELETE CASCADE)`, true},
		{`CREATE INDEX "finding_idx" ON "finding" ("a")`, false},
		{`CREATE TABLE "finding" ("a" INTEGER REFERENCES "product" ("id") ON DELETE CASCADE ON UPDATE CASCADE)`, false},
	} {
		if got := len(bareIn(c.statement)) > 0; got != c.bare {
			t.Errorf("%s: reported bare = %v (%v), want %v", c.statement, got, bareIn(c.statement), c.bare)
		}
	}
}

func TestEveryIdentifierInTheSchemaIsQuoted(t *testing.T) {
	// Every identifier the schema declares is quoted, and a check against the
	// list of words the engines reserve is strictly weaker: a name nobody has
	// reserved yet passes it.
	//
	// Read from the database rather than from the migration source, on the
	// same principle as the index test beside this: what matters is the schema
	// an operator ends up with. The source-reading gate is blind to a name
	// built by concatenation, which is the safe direction for a check that
	// fails a build and not a reason to have only that check.
	//
	// SQLite alone, for the reason the index test gives at length: this asks
	// what we wrote rather than what an engine did with it, and SQLite is the
	// one engine that hands back the statement as it was typed. So what a
	// migration writes only for another engine is not read here; the
	// source-reading reserved-word gate is what reaches that.
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		if err := schema.Up(ctx, db, quiet()); err != nil {
			t.Fatalf("migrate up: %v", err)
		}
		rows, err := db.QueryContext(ctx,
			`SELECT "name", "sql" FROM "sqlite_master" WHERE "sql" IS NOT NULL`)
		if err != nil {
			t.Fatalf("read the schema back: %v", err)
		}
		defer func() { _ = rows.Close() }()

		read := 0
		for rows.Next() {
			var name, statement string
			if err := rows.Scan(&name, &statement); err != nil {
				t.Fatalf("scan: %v", err)
			}
			// The bookkeeping table belongs to the migration library and is
			// not ours to spell.
			if strings.HasPrefix(name, "goose_") || strings.HasPrefix(name, "sqlite_") {
				continue
			}
			read++
			for _, where := range bareIn(statement) {
				t.Errorf("%s: %s is written bare — a reserved word is only reserved when it is",
					name, where)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("reading the schema: %v", err)
		}
		// A test that read nothing is a test that passed for the wrong
		// reason, which is the shape this whole finding is about.
		if read < 30 {
			t.Fatalf("only %d objects were read back, so this checked almost nothing", read)
		}
		t.Logf("%d objects checked", read)
	})
}

// withoutComments drops what a migration says about its own columns. The prose
// that makes a schema legible is full of the words this looks for.
func withoutComments(statement string) string {
	var kept strings.Builder
	for line := range strings.SplitSeq(statement, "\n") {
		if cut := strings.Index(line, "--"); cut >= 0 {
			line = line[:cut]
		}
		kept.WriteString(line)
		kept.WriteString("\n")
	}
	return kept.String()
}

// body is what is inside a declaration's outermost parentheses, which is where
// the columns are. An index's column list is in there too and is quoted by the
// same rule.
func body(statement string) string {
	open := strings.Index(statement, "(")
	shut := strings.LastIndex(statement, ")")
	if open < 0 || shut <= open {
		return ""
	}
	return statement[open+1 : shut]
}
