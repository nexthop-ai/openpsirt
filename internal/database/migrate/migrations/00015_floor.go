package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upFloor, downFloor)
}

// What a product considers worth triaging.
//
// Five thousand findings is a list nobody reads, and the ones that drown it
// are the ones nobody was ever going to act on. Below this line a finding is
// still recorded, still counted and still reportable — it leaves the working
// list, not the system, because an auditor asking what we knew is entitled to
// an answer whether or not it was worth an afternoon.
//
// On the product rather than in application_setting because products differ in
// what they can afford to ignore: one line for a whole estate is either too
// strict somewhere or too loose somewhere else. Null means the deployment's
// own line applies, which is the ordinary case and is why this is not NOT NULL
// — a product with no opinion should not have to state the default, or it
// would stop following it when the default changes.
func upFloor(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}
	statements := []string{
		`ALTER TABLE "product" ADD COLUMN "triage_floor" ` + t.kind + ` NULL`,
	}
	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downFloor(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{`ALTER TABLE "product" DROP COLUMN "triage_floor"`} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
