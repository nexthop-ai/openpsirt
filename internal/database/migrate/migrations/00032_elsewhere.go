package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upElsewhere, downElsewhere)
}

// Where the work is happening.
//
// **A stored link, and nothing is sent to it.** A hand-off to a tracker was
// recorded as one thing and it is two: a link has no egress at all, needs no
// configuration and connects a fix target declared here to the work being done
// there, while the half that *sends* is an outbound request a deployment has
// to decide to allow. Splitting them is what makes the cheap half
// available without that decision.
//
// **On the fix target and on the claim**, because both are things somebody
// does elsewhere: a target is a promise to change code and a claim is a
// judgment somebody may be arguing about in a ticket.
func upElsewhere(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		// Free text rather than a URL type: what a deployment tracks work in
		// is theirs, and a scheme allowlist here would refuse the internal
		// tool half of them use. Nothing fetches it, so nothing is exposed by
		// what it says — it is displayed as a link and encoded on the way out
		// like every other piece of text somebody typed.
		`ALTER TABLE "claim" ADD COLUMN "elsewhere" ` + t.free + ` NULL`,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downElsewhere(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{
		`ALTER TABLE "claim" DROP COLUMN "elsewhere"`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
