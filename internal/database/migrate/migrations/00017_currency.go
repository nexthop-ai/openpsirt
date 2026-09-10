package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upCurrency, downCurrency)
}

// Whether we are behind upstream, and whether upstream is still moving.
//
// Two facts, not a judgment about a project's health. The first says whether
// we are behind. The second says whether the thing is still being worked on —
// a newest release four years old says a dependency may need replacing,
// without anybody having to rate a project as alive or dead.
//
// Together they answer the question neither does alone: an issue disclosed
// *after* a component's newest release and still unfixed says upstream has
// shipped nothing since the flaw became known, which is the reason there is no
// fix, reached by comparing two dates rather than by rating anybody.
//
// Checked is kept separately from released so that "we have never asked" and
// "we asked and it has not moved" are different states. Without it a component
// nobody could look up is indistinguishable from one that is current.
//
// Only for what we build ourselves. For a distribution package the
// distribution is the maintainer and its release date says nothing about the
// software inside, which is why the columns are on the component rather than
// anything being inferred for everything.
func upCurrency(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}
	statements := []string{
		`ALTER TABLE "component" ADD COLUMN "latest_version" ` + t.free + ` NULL`,
		`ALTER TABLE "component" ADD COLUMN "latest_released_at" ` + t.timestamp + ` NULL`,
		`ALTER TABLE "component" ADD COLUMN "latest_checked_at" ` + t.timestamp + ` NULL`,
	}
	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downCurrency(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{
		`ALTER TABLE "component" DROP COLUMN "latest_checked_at"`,
		`ALTER TABLE "component" DROP COLUMN "latest_released_at"`,
		`ALTER TABLE "component" DROP COLUMN "latest_version"`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
