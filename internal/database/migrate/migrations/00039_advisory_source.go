package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upAdvisorySource, downAdvisorySource)
}

// The suppliers whose published advisories this deployment fetches.
//
// A supplier's security advisory already arrives by upload, which is somebody
// deciding that one document is worth reading. A supplier publishes hundreds a
// year, and the ones about a component a build here ships are not knowable in
// advance, so the deliberate act is choosing the publisher rather than choosing
// the document.
//
// Per product, because that is what a claim is recorded against. A supplier
// feeding two products is two rows, and each supersedes only its own product's
// claims — which is what keeps withdrawing one from touching the other.
//
// Named as well as addressed, for the reason a destination is: the name is what
// a screen and a log line call it, and an address a supplier moves is a change
// to a row rather than a different supplier.
func upAdvisorySource(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "advisory_source" (
			"id"           ` + t.id + `,
			"product_id"   ` + t.ref + ` NOT NULL,
			-- What it is called, lowered, which is what a name typed here is
			-- matched by. Normalizing the stored value rather than comparing
			-- loosely is what makes every engine agree without any of them
			-- being asked to.
			"name"         ` + t.name + ` NOT NULL,
			-- The spelling somebody typed, which is what gets shown back.
			"display_name" ` + t.name + ` NOT NULL,
			-- Where the supplier describes what they publish: the CSAF
			-- provider description, which names the feeds the documents are
			-- listed in. An address rather than a document, because a
			-- publisher issues one advisory per issue and a list of them is
			-- the only thing that stays at one address.
			"url"          ` + t.free + ` NOT NULL,
			-- How far through what a publisher lists this source has been
			-- read: the moment, and the address that moment was last read at.
			--
			-- A pair rather than a moment, because a publisher stamps a batch
			-- of documents with one moment and a date-only stamp gives a whole
			-- day the same one. Read as a moment alone, a cycle that stopped
			-- inside such a group would leave the mark on that moment and skip
			-- the rest of the group for ever.
			--
			-- The address is kept as its digest, so the comparison that orders
			-- two marks is over lower-case hexadecimal. Every engine orders
			-- those the same way whatever its collation, which a comparison
			-- over addresses themselves does not.
			"caught_up_to"   ` + t.timestamp + ` NULL,
			"caught_up_mark" ` + t.hash + ` NULL,
			-- When a pass last tried this supplier, when one last succeeded,
			-- and what stopped the last one. Two moments rather than one: an
			-- attempt that failed still happened, so a single moment reads as
			-- a supplier answering fine right up to the failure it is
			-- reporting — and "unreachable for a week" is only visible as the
			-- gap between them.
			"fetched_at"   ` + t.timestamp + ` NULL,
			"reached_at"   ` + t.timestamp + ` NULL,
			"failed"       ` + t.free + ` NULL,
			"created_by"   ` + t.ref + ` NOT NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			-- Retired rather than deleted, like every other configured thing:
			-- what was taken from where is a question asked afterwards, and
			-- the claims already recorded name this publisher.
			"retired_at"   ` + t.timestamp + ` NULL,
			CONSTRAINT "advisory_source_named_once" UNIQUE ("product_id", "name"),
			CONSTRAINT "advisory_source_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id"),
			CONSTRAINT "advisory_source_by_fk" FOREIGN KEY ("created_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// What the pass reads: every source still configured, across every
		// product, the one longest untried first. Without it that is a scan of
		// the table on every cycle, over a table whose size is the number of
		// products an estate holds times the publishers each reads from.
		`CREATE INDEX "advisory_source_due_idx" ON "advisory_source"
			("retired_at", "fetched_at")`,
	}

	return apply(ctx, tx, statements)
}

func downAdvisorySource(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "advisory_source")
}
