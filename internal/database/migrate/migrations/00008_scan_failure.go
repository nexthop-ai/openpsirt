package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upScanFailure, downScanFailure)
}

// Why a scan that was taken could not be read.
//
// The status alone says that something went wrong and nothing about what. A
// producer whose files cannot be read has to be able to see the reason where
// they see the scan, rather than in a log only an operator of this deployment
// can reach.
func upScanFailure(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		`ALTER TABLE scan ADD COLUMN failure ` + t.text + ` NULL`,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downScanFailure(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `ALTER TABLE scan DROP COLUMN failure`)
	return err
}
