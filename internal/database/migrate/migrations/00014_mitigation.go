package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upMitigation, downMitigation)
}

// What actually stops a vulnerability, where a dismissal rests on something
// stopping it.
//
// Every other recognized reason for something not applying is a claim about
// code, and code is what makes a decision lapse: the version moves, the key
// changes, and somebody is asked again. `inline_mitigations_already_exist` is
// a claim about configuration — a rule, a setting, a service that is not
// exposed — which can be removed with no version moving at all. Nothing here
// watches configuration, so that claim can go quietly false while the tool
// still believes it.
//
// Naming the control does not close that gap, and it is not pretended to. It
// is the difference between a claim somebody can go and check and one nobody
// can, and it is the justification an auditor asks about first, because the
// protection lives outside the software.
//
// Nullable because it belongs to one justification out of five, and because
// every claim recorded before this existed has no answer — a column that
// demanded one would be asserting something about claims nobody asked.
func upMitigation(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}
	statements := []string{
		`ALTER TABLE "claim" ADD COLUMN "mitigation" ` + t.text + ` NULL`,
	}
	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downMitigation(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{`ALTER TABLE "claim" DROP COLUMN "mitigation"`} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
