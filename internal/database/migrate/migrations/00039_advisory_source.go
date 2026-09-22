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
			-- What it is called, so a screen and a log line can name it, and
			-- the half of its identity that does not move when the supplier
			-- reorganizes their site.
			"name"         ` + t.name + ` NOT NULL,
			-- Where the supplier describes what they publish: the CSAF
			-- provider description, which names the feeds the documents are
			-- listed in. An address rather than a document, because a
			-- publisher issues one advisory per issue and a list of them is
			-- the only thing that stays at one address.
			"url"          ` + t.free + ` NOT NULL,
			-- The newest moment in the feed this source has been read to.
			-- Null until the first pass, which is what makes a source
			-- configured today start at today rather than at a publisher's
			-- whole history.
			"caught_up_to" ` + t.timestamp + ` NULL,
			-- When a pass last reached it and what stopped the last one, so
			-- an operator can see a supplier that has been unreachable for a
			-- week rather than inferring it from missing evidence.
			"fetched_at"   ` + t.timestamp + ` NULL,
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
		// product, oldest fetch first. Without this that is a scan of the
		// table on every cycle, which is small now and is the shape that
		// stops being small when a deployment configures a supplier per
		// product across an estate.
		`CREATE INDEX "advisory_source_due_idx" ON "advisory_source"
			("retired_at", "fetched_at")`,
	}

	return apply(ctx, tx, statements)
}

func downAdvisorySource(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "advisory_source")
}
