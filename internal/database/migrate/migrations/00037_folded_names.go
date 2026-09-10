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
	goose.AddMigrationContext(upFoldedNames, downFoldedNames)
}

// A component's name, folded once on the way in.
//
// **The four engines do not fold alike, and every match on a component's name
// asked an engine to.** SQLite's LOWER folds ASCII and nothing else while the
// three servers fold the whole character set, so a component named with any
// letter outside ASCII matched a routing rule, a search or a publisher's
// statement on three engines and not on the fourth — and which engine a
// deployment happened to run decided whether a rule swept it or a publisher's
// judgment reached it. Nothing reported the difference, because both answers
// look like a correct answer.
//
// The VEX statement was fixed this way first: fold on write, compare with
// equality. This is the other half — the component side of the same
// comparisons — and the same reasoning as every other name people type.
//
// **It also makes the comparisons use an index.** LOWER(c.name) cannot, so
// every routing sweep and every component search was a scan of the component
// table; a rule naming a source package walked every component in the
// deployment once per build.
//
// Backfilled with the engine's own LOWER, which is right for what is already
// stored: the divergence is between engines, and a deployment has only ever
// run one. Anything arriving after this is folded in Go, so all four agree
// from here.
func upFoldedNames(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	for _, stmt := range []string{
		// Bounded, unlike the names they fold. The stored name is unbounded
		// because nothing bounds what a producer puts in a scan file, and a
		// bounded column there would fail a whole scan over one long value.
		// This one exists to be looked up, and an index needs a width — the
		// same trade DESIGN-database.md records for every other indexed text
		// column, resolved the same way: truncated on the way in rather than
		// refused, because two names agreeing for a hundred and ninety-one
		// characters are the same name by any reading.
		//
		// Nullable, because a row written before this has neither until the
		// backfill below runs, and because a component with no upstream name
		// recorded has no folded one either.
		`ALTER TABLE "component" ADD COLUMN "name_folded" ` + t.name + ` NULL`,
		`ALTER TABLE "component" ADD COLUMN "upstream_folded" ` + t.name + ` NULL`,
		`UPDATE "component" SET "name_folded" = LOWER(SUBSTR("name", 1, 191))`,
		`UPDATE "component" SET "upstream_folded" = LOWER(SUBSTR("upstream_name", 1, 191))
			WHERE "upstream_name" IS NOT NULL`,
		// What a routing rule and a component search look one up by. The
		// upstream name first, because a rule names a source package: that is
		// the key one rule uses to reach every binary package built from it.
		`CREATE INDEX "component_folded_idx" ON "component" ("name_folded")`,
		`CREATE INDEX "component_upstream_folded_idx" ON "component" ("upstream_folded")`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

// Two engines name the table when dropping an index and two do not.
func downFoldedNames(ctx context.Context, tx *sql.Tx) error {
	drops := []string{
		`DROP INDEX "component_upstream_folded_idx"`,
		`DROP INDEX "component_folded_idx"`,
	}
	switch migrate.EngineFrom(ctx) {
	case database.MySQL, database.MariaDB:
		drops = []string{
			`DROP INDEX "component_upstream_folded_idx" ON "component"`,
			`DROP INDEX "component_folded_idx" ON "component"`,
		}
	}
	for _, stmt := range append(drops,
		`ALTER TABLE "component" DROP COLUMN "upstream_folded"`,
		`ALTER TABLE "component" DROP COLUMN "name_folded"`,
	) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
