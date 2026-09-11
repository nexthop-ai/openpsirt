package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upAssessment, downAssessment)
}

// What we think of an issue, as against what was published about it.
//
// Recorded against the issue rather than against a place. A published rating
// being wrong, or a report being disputed, is one statement about the
// vulnerability — not a statement about where it sits. Keyed to a place it
// would have to be repeated at each one and would lapse on a version change
// that had nothing to do with it: the rating did not stop being wrong because
// somebody rebuilt.
//
// The rating in force lives on the vulnerability itself, as
// `assessed_severity`, and everything that ranks or filters reads it through
// one expression with the published one as its fallback. That keeps the claim
// in one place and the reading of it in one place — this project's own
// recurring lesson is that every identity and expiry bug came from letting one
// fact into two rules.
//
// The published rating is never overwritten. A rating of ours shown where the
// world's rating goes reads as the world's, and the first person to check
// against the public record finds a discrepancy nobody declared.
func upAssessment(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{

		// One claim per issue. state is 'proposed', 'live' or
		// 'withdrawn'.
		//
		// Rating something worse takes effect at once and rating it
		// milder waits for a second person, so a claim can be recorded
		// and not yet in force — which is why the rating in force is a
		// separate column on the vulnerability rather than read from
		// here.
		`CREATE TABLE "assessment" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"severity"         ` + t.kind + ` NOT NULL,
			-- What was published when this was made, kept so a later reader
			-- can see what we were disagreeing with rather than having to
			-- infer it from a feed that has since moved on.
			"published"     ` + t.kind + ` NULL,
			"reasoning"     ` + t.text + ` NOT NULL,
			"state"         ` + t.kind + ` NOT NULL,
			"needs_approval" ` + t.boolean + ` NOT NULL,
			"proposed_by"   ` + t.ref + ` NOT NULL,
			"proposed_at"   ` + t.timestamp + ` NOT NULL,
			"decided_by"    ` + t.refNull + ` NULL,
			"decided_at"    ` + t.timestamp + ` NULL,
			-- The issue this is a claim about, while it is still a live claim:
			-- the same value as "vulnerability_id" until the claim is
			-- withdrawn, and null after. Under a unique constraint that is
			-- how "one live claim per issue" is enforced by the database
			-- rather than by a check — null values do not collide in a unique
			-- index on any of the four engines, so any number of withdrawn
			-- claims may sit beside the live one, and two proposals arriving
			-- at once cannot both get through. A read-then-write check is
			-- exactly the shape both of them walk through.
			--
			-- No foreign key of its own: "vulnerability_id" already carries
			-- one, and this column is the mechanism that holds the rule
			-- rather than a second reference to the issue.
			"live_vulnerability_id" ` + t.refNull + ` NULL,
			CONSTRAINT "assessment_live_unique" UNIQUE ("live_vulnerability_id"),
			CONSTRAINT "assessment_vulnerability_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "assessment_proposer_fk" FOREIGN KEY ("proposed_by")
				REFERENCES "person"("id"),
			CONSTRAINT "assessment_decider_fk" FOREIGN KEY ("decided_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// Reading an issue's claims, live and withdrawn alike. What holds the
		// rule that only one of them is live is the unique constraint above,
		// not this.
		`CREATE INDEX "assessment_issue_idx" ON "assessment" ("vulnerability_id", "state")`,
		`CREATE INDEX "assessment_waiting_idx" ON "assessment" ("state", "needs_approval")`,
	}
	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

// The indexes go with the table and are not dropped separately.
//
// Dropping them first is what every other migration here avoids, and this one
// did it anyway: MySQL and MariaDB refuse to drop an index a foreign key needs
// to enforce itself, so "assessment_issue_idx" — which leads with
// vulnerability_id — cannot go while the constraint on that column stands. The
// rollback failed on two engines and passed on the other two.
func downAssessment(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{
		`DROP TABLE "assessment"`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
