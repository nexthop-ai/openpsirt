package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upTrail, downTrail)
}

// What somebody changed about how this deployment works.
//
// **Who, what, before, after and when**. Three administrative levers
// silently rewrite what this tool reports: changing the deadline policy
// recomputes every open finding's deadline, raising the triage floor takes the
// deadline off everything below it, and an end-of-life date takes it off
// everything past it. None of them recorded who moved it — a setting carried
// when it changed and not by whom, a role grant when it was withdrawn and not
// who granted it.
//
// For a tool whose entire output is evidence, that is the evidence being
// movable with nothing recording that anybody moved it. It is the same gap the
// triage history closes, one layer above it.
//
// **Both values are text, and both are kept.** What a setting held before is
// not derivable afterwards, and "who raised the floor to critical" is only half
// the question somebody asks — the other half is what it was. A value that was
// unset is an absent before rather than an empty one, because "nobody had set
// it" and "somebody set it to nothing" are different acts.
func upTrail(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		`CREATE TABLE "admin_change" (
			"id"       ` + t.id + `,
			"at"       ` + t.timestamp + ` NOT NULL,
			-- Who. Never null: a change nobody made is a change nothing
			-- records, which is the state this table exists to end.
			"by"       ` + t.ref + ` NOT NULL,
			-- What kind of thing moved, and which one of them. The kind is
			-- what a reader filters by; the name is what they search for.
			"kind"     ` + t.kind + ` NOT NULL,
			"about"    ` + t.name + ` NOT NULL,
			-- What it held and what it holds. Null before means nobody had
			-- set it; null after means it was cleared.
			"was"      ` + t.text + ` NULL,
			"became"   ` + t.text + ` NULL,
			CONSTRAINT "admin_change_by_fk" FOREIGN KEY ("by") REFERENCES "person"("id")
		)` + t.suffix,

		// Newest first, which is the only order this is ever read in, and
		// narrowed by kind because that is the only filter it takes.
		`CREATE INDEX "admin_change_recent_idx" ON "admin_change" ("at", "kind")`,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downTrail(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{`DROP TABLE "admin_change"`} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
