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

// bareColumn matches a column declaration opening with an unquoted name. The
// words excluded are the ones that open a table constraint rather than a
// column.
var bareColumn = regexp.MustCompile(
	`(?im)^\s*(?:(CONSTRAINT|PRIMARY|UNIQUE|FOREIGN|CHECK|REFERENCES|ON|DEFAULT|NOT|NULL)\b|([A-Za-z_][A-Za-z0-9_]*)\s)`)

func TestEveryIdentifierInTheSchemaIsQuoted(t *testing.T) {
	// AGENTS.md states this three times and two things claimed to enforce it.
	// Neither did: the gate named for it compared each name against a list of
	// 321 words the four engines reserve, which is a strictly weaker property
	// — a name nobody has reserved yet passes, and MySQL 8.0 reserved four
	// more without anything refreshing the list. And the test named for it
	// built its own probe table, so it could not observe a single identifier
	// in the schema.
	//
	// **Read from the database rather than from the migration source**, on the
	// same principle as the index test beside this: what matters is the schema
	// an operator ends up with. The source-reading gate is blind to a name
	// built by concatenation, which is the safe direction for a check that
	// fails a build and not a reason to have only that check.
	//
	// SQLite alone, for the reason the index test gives at length: this asks
	// what we wrote rather than what an engine did with it, and SQLite is the
	// one engine that hands back the statement as it was typed.
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
			bare := withoutComments(statement)
			for _, m := range bareAfter.FindAllStringSubmatch(bare, -1) {
				t.Errorf("%s: %s names %q bare — a reserved word is only reserved when it is",
					name, strings.ToUpper(m[1]), m[2])
			}
			for _, m := range bareColumn.FindAllStringSubmatch(body(bare), -1) {
				if m[2] != "" {
					t.Errorf("%s: the column %q is declared bare", name, m[2])
				}
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
