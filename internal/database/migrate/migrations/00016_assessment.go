package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upAssessment, downAssessment)
}

// One product's own view of an issue, as against what was published about it.
//
// Recorded against the issue rather than against a place, and against one
// product rather than against the deployment. Keyed to a place it would have
// to be repeated at each one and would lapse on a version change that had
// nothing to do with it: the rating did not stop being wrong because somebody
// rebuilt. Keyed to nothing at all it was one statement for everybody, which
// let a rating made by somebody holding one product move the deadline and the
// triage line in a product they cannot see, and refused a second team any
// rating of their own — a rating is a judgment about how a component is used,
// and two products do not use one the same way.
//
// The rating in force lives in "issue_rating", one row per issue and product,
// and everything that ranks or filters reads it through one expression with
// the published rating as its fallback. That keeps the claim in one place and
// the reading of it in one place — this project's own recurring lesson is that
// every identity and expiry bug came from letting one fact into two rules.
//
// Nothing inherits. A product nobody has rated the issue in shows the
// published rating until somebody on that team looks, because a rating
// arriving from a product they cannot see is the thing this shape removes.
//
// The published rating is never overwritten. A rating of ours shown where the
// world's rating goes reads as the world's, and the first person to check
// against the public record finds a discrepancy nobody declared.
func upAssessment(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{

		// One claim per issue and product. state is 'proposed', 'live'
		// or 'withdrawn'.
		//
		// Rating something worse takes effect at once and rating it
		// milder waits for a second person, so a claim can be recorded
		// and not yet in force — which is why the rating in force is a
		// separate table rather than read from here.
		`CREATE TABLE "assessment" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- The product this is a rating for. Recording, agreeing to and
			-- withdrawing one all ask for triage on this product, so the
			-- column is what the authorization is asked about rather than a
			-- label beside it.
			"product_id"       ` + t.ref + ` NOT NULL,
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
			-- withdrawn, and null after. Paired with the product under a
			-- unique constraint that is how "one live claim per issue and
			-- product" is enforced by the database rather than by a check —
			-- null values do not collide in a unique index on any of the four
			-- engines, so any number of withdrawn claims may sit beside the
			-- live one, and two proposals arriving at once cannot both get
			-- through. A read-then-write check is exactly the shape both of
			-- them walk through.
			--
			-- The product is repeated in the pair rather than the constraint
			-- reading "product_id" itself, because the nulls are what release
			-- a withdrawn claim and "product_id" is never null.
			--
			-- No foreign key of its own: "vulnerability_id" already carries
			-- one, and this column is the mechanism that holds the rule
			-- rather than a second reference to the issue.
			"live_vulnerability_id" ` + t.refNull + ` NULL,
			CONSTRAINT "assessment_live_unique" UNIQUE ("live_vulnerability_id", "product_id"),
			CONSTRAINT "assessment_vulnerability_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "assessment_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id"),
			CONSTRAINT "assessment_proposer_fk" FOREIGN KEY ("proposed_by")
				REFERENCES "person"("id"),
			CONSTRAINT "assessment_decider_fk" FOREIGN KEY ("decided_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// Reading an issue's claims in a product, live and withdrawn alike.
		// The rule that only one of them is live is held by the unique
		// constraint above, not this.
		`CREATE INDEX "assessment_issue_idx" ON "assessment" ("vulnerability_id", "product_id", "state")`,
		`CREATE INDEX "assessment_waiting_idx" ON "assessment" ("state", "needs_approval")`,

		// The rating in force, one row per issue and product.
		//
		// Separate from the claim above because a milder rating waits for a
		// second person: a claim exists before it decides anything, and what
		// ranks has to be readable without knowing which claims are live. A
		// row is written when a rating takes effect and removed when it is
		// withdrawn, so its presence is the whole of "somebody here rates
		// this differently".
		//
		// Read by a left join keyed on the issue and the product, with the
		// published rating as the fallback, through one expression. The
		// alternative was a copy on every finding, and a finding opened
		// tomorrow by a component that newly pulls the library in would carry
		// the rating only if the applying path remembered to fetch it. A
		// joined table cannot drift that way.
		`CREATE TABLE "issue_rating" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			"severity"         ` + t.kind + ` NOT NULL,
			CONSTRAINT "issue_rating_unique" UNIQUE ("vulnerability_id", "product_id"),
			CONSTRAINT "issue_rating_vulnerability_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "issue_rating_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id")
		)` + t.suffix,
	}
	return apply(ctx, tx, statements)
}

// The indexes go with the table and are not dropped separately.
//
// Dropping them first is what every other migration here avoids, and this one
// did it anyway: MySQL and MariaDB refuse to drop an index a foreign key needs
// to enforce itself, so "assessment_issue_idx" — which leads with
// vulnerability_id — cannot go while the constraint on that column stands. The
// rollback failed on two engines and passed on the other two.
func downAssessment(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "issue_rating", "assessment")
}
