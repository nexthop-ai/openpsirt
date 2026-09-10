package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upDeadline, downDeadline)
}

// When a finding is due, worked out once rather than on every request.
//
// A deadline is when the finding was first seen plus how long something of
// that urgency may stay open. Derived on demand it costs a pass over every
// open finding **per urgency band**, because each band allows a different
// number of days and the window has to be applied before the rows are read
// rather than after — measured at about eight seconds over 441,108 findings,
// on the screen whose entire purpose is noticing something before it runs out.
//
// Stored, the same question is an indexed range scan. The column is nullable
// because a finding recorded before this existed has no answer until the next
// scan reopens it, and a null deadline is honestly "not known" rather than
// "not due".
//
// The index leads with the two columns that are always compared — a finding
// that is closed or already answered is not running out of anything — so the
// deadline itself is the range at the end of a narrow prefix.
func upDeadline(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		`ALTER TABLE "finding" ADD COLUMN "due_at" ` + t.timestamp + ` NULL`,
		`CREATE INDEX "finding_due_idx" ON "finding" ("closed_at", "suppressed_by", "due_at")`,
	}
	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

// Going back needs the foreign key out of the way on MySQL and MariaDB.
//
// InnoDB insists every foreign key has an index it can enforce itself with,
// and it picks one rather than owning one: no other index on "finding" leads
// with closed_run_id, so making this one made it the constraint's. Dropping it
// is then refused, and the refusal is what a rollback runs into rather than
// anything a reader of the "up" would expect.
//
// So the constraint comes off, the index goes, and the constraint goes back —
// at which point InnoDB creates its own index for it again, which is the state
// this migration found. PostgreSQL and SQLite have no such rule and drop the
// index as asked.
func downDeadline(ctx context.Context, tx *sql.Tx) error {
	var statements []string
	switch migrate.EngineFrom(ctx) {
	case database.MySQL, database.MariaDB:
		statements = []string{
			`ALTER TABLE "finding" DROP FOREIGN KEY "finding_closed_run_id_fk"`,
			`DROP INDEX "finding_due_idx" ON "finding"`,
			`ALTER TABLE "finding" ADD CONSTRAINT "finding_closed_run_id_fk"
				FOREIGN KEY ("closed_run_id") REFERENCES "scan_run"("id")`,
			`ALTER TABLE "finding" DROP COLUMN "due_at"`,
		}
	default:
		statements = []string{
			`DROP INDEX "finding_due_idx"`,
			`ALTER TABLE "finding" DROP COLUMN "due_at"`,
		}
	}
	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
