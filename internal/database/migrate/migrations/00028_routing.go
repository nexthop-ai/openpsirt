package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upRouting, downRouting)
}

// A standing rule that hands work nobody holds to a team.
//
// **It matches on component identity as well as on a place in the tree.** The
// upstream name is the key that matters: one rule naming a source package
// catches every binary package built from it, wherever they sit. The earlier
// framing had this as a subtree rule, and the case that motivates it is not a
// subtree at all — a kernel is one source package appearing at many places
// under many consumers, so a subtree rule would need a line per place and would
// still miss tomorrow's.
//
// **Ordered, and the first match wins**. An unwritten precedence rule
// is forgettable, and the question it answers — where did this come from — is
// asked months later by somebody who was not there. Which rule placed a finding
// is written on the finding, the same choice already made for how a match was
// made: a placement nobody can explain is one nobody can correct, and at this
// fan-out there will be thousands of them.
func upRouting(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		`CREATE TABLE "routing_rule" (
			"id"         ` + t.id + `,
			"product_id" ` + t.ref + ` NOT NULL,
			-- Where work lands. A team rather than a person, because what a
			-- rule makes is a queue somebody picks out of.
			"team_id"    ` + t.ref + ` NOT NULL,
			-- What to call it, so a placement can be explained in words rather
			-- than by an identifier.
			"name"       ` + t.free + ` NOT NULL,
			-- Where it sits among the others. First match wins, so this is the
			-- whole of the precedence and it is written down rather than
			-- implied by insertion order.
			"ordinal"    ` + t.ref + ` NOT NULL,
			-- The two ways a rule matches, and at least one is required. The
			-- upstream name is the one that matters: it catches every binary
			-- package of a source package at once. The subtree is the other
			-- kind, kept because a rule about a part of the product is a real
			-- thing people want.
			"upstream"   ` + t.name + ` NULL,
			"beneath"    ` + t.name + ` NULL,
			"created_by" ` + t.ref + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			-- Retired rather than deleted, for the reason a team is: a finding
			-- says which rule placed it, and that has to keep resolving to
			-- something a screen can name.
			"retired_at" ` + t.timestamp + ` NULL,
			CONSTRAINT "routing_rule_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "routing_rule_team_fk" FOREIGN KEY ("team_id") REFERENCES "team"("id"),
			CONSTRAINT "routing_rule_by_fk" FOREIGN KEY ("created_by") REFERENCES "person"("id")
		)` + t.suffix,

		// The rules of one product, in the order they are tried.
		`CREATE INDEX "routing_rule_order_idx"
			ON "routing_rule" ("product_id", "retired_at", "ordinal")`,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downRouting(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{`DROP TABLE "routing_rule"`} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
