package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upIssuance, downIssuance)
}

// That an advisory went out.
//
// A fact about a moment rather than a derived value. What was published on
// a date cannot be worked out again once the record it was generated from has
// moved on — a release is added, a decision is revised, a fix lands — so if it
// is not written down when it happens it is gone.
//
// Without it a second advisory for the same flaw cannot carry a revision
// history or increment its version, and both are things CSAF validators
// check. A document that fails validation is one a customer's tooling drops,
// which is the failure that looks like nothing happening.
//
// The published advisory itself stays the platform's rather than ours: this
// records the act, not the document. The digest is what makes the two
// answerable against each other — "is what is published still what we
// generated" is a question with a yes or no, rather than a comparison of two
// documents nobody kept.
func upIssuance(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "advisory_issuance" (
			"id"               ` + t.id + `,
			"product_id"       ` + t.ref + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- Which issuance this is, counting from one. It is what the
			-- document's version says, and a validator checks that a revised
			-- document carries a higher one than the last.
			"ordinal"          ` + t.ref + ` NOT NULL,
			-- What went out, hashed. The document is not kept here — it
			-- belongs to whoever published it — and the digest is what makes
			-- "is what is published still what we generated" answerable.
			"digest"           ` + t.hash + ` NOT NULL,
			-- What somebody wants said about this revision, where they said
			-- anything. A revision history whose every entry reads the same is
			-- one nobody reads.
			"summary"          ` + t.free + ` NULL,
			"issued_by"        ` + t.ref + ` NOT NULL,
			"issued_at"        ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "advisory_issuance_once" UNIQUE ("product_id", "vulnerability_id", "ordinal"),
			CONSTRAINT "advisory_issuance_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "advisory_issuance_issue_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "advisory_issuance_by_fk" FOREIGN KEY ("issued_by") REFERENCES "person"("id")
		)` + t.suffix,
	}

	return apply(ctx, tx, statements)
}

func downIssuance(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "advisory_issuance")
}
