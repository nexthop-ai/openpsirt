package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upComponentCPE, downComponentCPE)
}

// The second identifier a component can carry.
//
// A package identifier is the one this system derives identity from, and it is
// what most feeds match on. It is not the only scheme in use: the platform
// enumeration is what the national vulnerability database keys on, and a
// scanner given one will match components a package identifier alone misses —
// vendor firmware, operating systems, appliances, anything never published to
// a package ecosystem.
//
// It is captured because a real producer emits it on the large majority of
// what it ships, and because a scan file is not kept once it has been read.
// Data discarded at ingest is not recoverable later by re-reading; it is
// recoverable only by asking the producer to build again.
//
// It is deliberately not part of identity. Identity is derived from the
// package identifier where there is one, and adding a second basis would move
// the identity of everything that carries both.
func upComponentCPE(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		`ALTER TABLE component ADD COLUMN cpe ` + t.text + ` NULL`,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downComponentCPE(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `ALTER TABLE component DROP COLUMN cpe`)
	return err
}
