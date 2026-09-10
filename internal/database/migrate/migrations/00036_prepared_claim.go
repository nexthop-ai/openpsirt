package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upPreparedClaim, downPreparedClaim)
}

// What a saved filter prepares.
//
// **A rule prepares a claim; a person proposes it.** A saved filter can carry
// an outcome, a justification and the reasoning, and opening it offers them
// prefilled — but a named person submits the claim as their own, and a second
// person approves it.
//
// The wider form was argued for and refused: a rule proposing its own pending
// claim leaves the approver as the only human judgment on it, which is exactly
// what making the claim the approver's unit was meant to prevent, and it puts a
// configuration file where a name belongs in the record. The difference shows
// up on the day a dismissal turns out to have been wrong and somebody asks who
// made it.
//
// **On the saved filter rather than in a table of its own.** What a rule *is*
// here is a narrowing plus what to say about what it catches, and those are
// one thing somebody names: a second table would make "the filter" and "the
// rule" two objects that have to be kept pointing at each other.
//
// All four columns absent is an ordinary saved filter, which is most of them.
func upPreparedClaim(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	for _, stmt := range []string{
		`ALTER TABLE "saved_filter" ADD COLUMN "outcome" ` + t.kind + ` NULL`,
		// Free text rather than the short kind column, which is what the
		// decision itself uses: the justification vocabulary is the format's
		// and its words run past sixteen characters —
		// "vulnerable_code_not_present" is twenty-seven, which one engine
		// truncates and another refuses.
		`ALTER TABLE "saved_filter" ADD COLUMN "justification" ` + t.free + ` NULL`,
		`ALTER TABLE "saved_filter" ADD COLUMN "reasoning" ` + t.text + ` NULL`,
		// How long a deferral it prepares, in days from whenever somebody
		// submits it. A date would be wrong the week after it was saved: what
		// a rule means is "put this off for a quarter", not "until 3 March".
		`ALTER TABLE "saved_filter" ADD COLUMN "defer_days" INTEGER NULL`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downPreparedClaim(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{
		`ALTER TABLE "saved_filter" DROP COLUMN "defer_days"`,
		`ALTER TABLE "saved_filter" DROP COLUMN "reasoning"`,
		`ALTER TABLE "saved_filter" DROP COLUMN "justification"`,
		`ALTER TABLE "saved_filter" DROP COLUMN "outcome"`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
