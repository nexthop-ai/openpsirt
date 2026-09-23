// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upAdvisory, downAdvisory)
}

// The advisory, the issues it covers, what it says, who agreed to it, and
// that it went out.
//
// An advisory is a record of its own under an identifier this deployment
// mints, rather than a document derived from one product and one issue. The
// standard carries vulnerabilities as an array and means the tracking
// identifier to be the publisher's own name for the document, so a key made of
// a product and an issue cannot express a document about two of them and hands
// out somebody else's name for one of them. Several embargoed flaws released
// together is one document on one date, which that key has no way to say.
//
// An issuance is a fact about a moment rather than a derived value. What was
// published on a date cannot be worked out again once the record it was
// generated from has moved on — a release is added, a decision is revised, a
// fix lands — so if it is not written down when it happens it is gone.
//
// Without it a second advisory cannot carry a revision history or increment
// its version, and both are things CSAF validators check. A document that
// fails validation is one a customer's tooling drops, which is the failure
// that looks like nothing happening.
//
// An edition is what the advisory says at a point, and an approval names one
// of them. The text a document carries is the company speaking, so a second
// person reads it before it leaves — and they read particular words, which is
// why the agreement names the edition rather than the advisory. Editing opens
// a new edition and takes back every approval standing on the one it replaced.
//
// The document that went out is kept beside the act. Whoever publishes owns
// the published advisory; what is held here is the bytes this deployment
// generated and handed over, which is the only copy of a moment that has
// passed. The digest beside it is over the part of those bytes that says what
// the document states, so "is what is published still what we generate" stays
// a question with a yes or no.
func upAdvisory(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	return apply(ctx, tx, advisoryStatements(t))
}

func advisoryStatements(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "advisory" (
			"id"         ` + t.id + `,
			-- The name a reader cites the document by, minted here: a prefix
			-- the deployment configures, the year, and a number within it.
			-- It belongs to the document rather than to whichever issue was
			-- first, and a revision keeps it.
			"identifier" ` + t.name + ` NOT NULL,
			-- The same name folded, which is what uniqueness and lookup are
			-- asked of. A name people type is matched without regard to
			-- capitals, and the engines disagree about how a comparison
			-- folds, so the folded value is stored rather than the
			-- comparison being asked to fold.
			"identifier_folded" ` + t.name + ` NOT NULL,
			-- The two parts the identifier was minted from, kept as numbers.
			-- Minting asks for the highest number in the current year, and
			-- taking that out of the identifier would mean parsing a string
			-- four engines parse differently. The identifier stays the name
			-- that was given, so a prefix changed later renames nothing.
			"minted_year"      ` + t.ref + ` NOT NULL,
			"mint_number"      ` + t.ref + ` NOT NULL,
			-- What the advisory says as it stands. An approval points at one
			-- edition rather than at the advisory, so this moving is exactly
			-- what withdraws an approval.
			--
			-- No foreign key: the table it points at is declared below and
			-- points back here, and neither engine that enforces order during
			-- a bulk delete would accept the cycle.
			"edition_id" ` + t.refNull + ` NULL,
			-- The moment the document dates itself from, frozen when the
			-- advisory first went out. Until then it is the earliest
			-- recording among the flaws it covers, worked out each time the
			-- document is generated; naming an older flaw afterwards would
			-- otherwise move a published document's first-release date, and
			-- with it the year folder a reader already found it in.
			"released_from" ` + t.timestamp + ` NULL,
			"minted_at"  ` + t.timestamp + ` NOT NULL,
			"minted_by"  ` + t.ref + ` NOT NULL,
			CONSTRAINT "advisory_identifier_once" UNIQUE ("identifier_folded"),
			CONSTRAINT "advisory_number_once" UNIQUE ("minted_year", "mint_number"),
			CONSTRAINT "advisory_by_fk" FOREIGN KEY ("minted_by") REFERENCES "person"("id")
		)` + t.suffix,

		`CREATE TABLE "advisory_edition" (
			"id"          ` + t.id + `,
			"advisory_id" ` + t.ref + ` NOT NULL,
			-- Which edition this is, counting from one. An approval names an
			-- edition, so the number is what a reader of the record follows
			-- to find out what somebody agreed to.
			"ordinal"     ` + t.ref + ` NOT NULL,
			-- What somebody titled it. The document falls back to naming the
			-- issues it covers, so this is absent until anybody says
			-- otherwise.
			"title"       ` + t.free + ` NULL,
			"written_by"  ` + t.ref + ` NOT NULL,
			"written_at"  ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "advisory_edition_once" UNIQUE ("advisory_id", "ordinal"),
			CONSTRAINT "advisory_edition_advisory_fk"
				FOREIGN KEY ("advisory_id") REFERENCES "advisory"("id"),
			CONSTRAINT "advisory_edition_by_fk"
				FOREIGN KEY ("written_by") REFERENCES "person"("id")
		)` + t.suffix,

		// The agreeing person, and what exactly they agreed to.
		//
		// Kept rather than reduced to a flag on the advisory, because an
		// approval that was later withdrawn is part of the record: it says a
		// second person did once agree, and to which edition.
		`CREATE TABLE "advisory_approval" (
			"id"           ` + t.id + `,
			"advisory_id"  ` + t.ref + ` NOT NULL,
			-- The edition agreed to, not the advisory. A second pair of eyes
			-- reads particular words; an approval that floated free of them
			-- would still be standing after somebody rewrote them, and
			-- nothing would report that.
			"edition_id"   ` + t.ref + ` NOT NULL,
			"approved_by"  ` + t.ref + ` NOT NULL,
			"approved_at"  ` + t.timestamp + ` NOT NULL,
			-- Taken back, by whom, which is not who gave it. An edit
			-- withdraws every approval standing on what it replaced, and the
			-- person who edited is the person who took the agreement back.
			"withdrawn_at" ` + t.timestamp + ` NULL,
			"withdrawn_by" ` + t.refNull + ` NULL,
			CONSTRAINT "advisory_approval_advisory_fk"
				FOREIGN KEY ("advisory_id") REFERENCES "advisory"("id"),
			CONSTRAINT "advisory_approval_edition_fk"
				FOREIGN KEY ("edition_id") REFERENCES "advisory_edition"("id"),
			CONSTRAINT "advisory_approval_by_fk"
				FOREIGN KEY ("approved_by") REFERENCES "person"("id"),
			CONSTRAINT "advisory_approval_back_fk"
				FOREIGN KEY ("withdrawn_by") REFERENCES "person"("id")
		)` + t.suffix,

		// On the edition, which is what the read asks for: every document
		// generated wants the agreements standing on what the advisory says
		// now. The advisory's own column is looked up only when an edit takes
		// agreements back, and the table holds an advisory a fortnight.
		`CREATE INDEX "advisory_approval_edition_idx" ON "advisory_approval" ("edition_id")`,

		`CREATE TABLE "advisory_issuance" (
			"id"          ` + t.id + `,
			-- Keyed on the advisory, which is what makes a revision of a
			-- document covering two issues one record rather than two.
			"advisory_id" ` + t.ref + ` NOT NULL,
			-- Which issuance this is, counting from one. It is what the
			-- document's version says, and a validator checks that a revised
			-- document carries a higher one than the last.
			"ordinal"     ` + t.ref + ` NOT NULL,
			-- The edition that went out, which is a fact about a moment. The
			-- advisory moves on to later editions and what was published
			-- does not, so asked of the advisory today a record of what went
			-- out in March answers with June's title.
			"edition_id"  ` + t.ref + ` NOT NULL,
			-- What went out, and the same bytes hashed.
			--
			-- The document is kept because it cannot be worked out again: a
			-- release is added, a decision is revised, a fix lands, and what
			-- would be generated today is a different document. A directory
			-- of published advisories serves the bytes that went out, and
			-- regenerating them would move a file whose date says it has not
			-- moved.
			--
			-- The digest is over the part of those bytes that says what the
			-- document states, so it answers "is what is published still
			-- what we generated" while the document answers "what was
			-- published". Both are written from the one document in the one
			-- statement.
			"document"    ` + t.free + ` NOT NULL,
			"digest"      ` + t.hash + ` NOT NULL,
			-- What somebody wants said about this revision, where they said
			-- anything. A revision history whose every entry reads the same is
			-- one nobody reads.
			"summary"     ` + t.free + ` NULL,
			"issued_by"   ` + t.ref + ` NOT NULL,
			"issued_at"   ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "advisory_issuance_once" UNIQUE ("advisory_id", "ordinal"),
			CONSTRAINT "advisory_issuance_advisory_fk"
				FOREIGN KEY ("advisory_id") REFERENCES "advisory"("id"),
			CONSTRAINT "advisory_issuance_edition_fk"
				FOREIGN KEY ("edition_id") REFERENCES "advisory_edition"("id"),
			CONSTRAINT "advisory_issuance_by_fk" FOREIGN KEY ("issued_by") REFERENCES "person"("id")
		)` + t.suffix,

		`CREATE TABLE "advisory_issue" (
			"id"               ` + t.id + `,
			"advisory_id"      ` + t.ref + ` NOT NULL,
			-- The product this issue is covered in. An issue in two products
			-- is two entries: the releases that carry it differ, and a status
			-- is stated about releases.
			"product_id"       ` + t.ref + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"added_at"         ` + t.timestamp + ` NOT NULL,
			"added_by"         ` + t.ref + ` NOT NULL,
			-- Taken back off, by whom. The row stays so that the act has
			-- somewhere to be written: deleted, who removed an issue from an
			-- advisory is a question nothing answers. Adding it again revives
			-- this row rather than writing a second one, which is what keeps
			-- the pair unique.
			"removed_at"       ` + t.timestamp + ` NULL,
			"removed_by"       ` + t.refNull + ` NULL,
			CONSTRAINT "advisory_issue_once"
				UNIQUE ("advisory_id", "product_id", "vulnerability_id"),
			CONSTRAINT "advisory_issue_advisory_fk"
				FOREIGN KEY ("advisory_id") REFERENCES "advisory"("id"),
			CONSTRAINT "advisory_issue_product_fk"
				FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "advisory_issue_issue_fk"
				FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "advisory_issue_by_fk" FOREIGN KEY ("added_by") REFERENCES "person"("id"),
			CONSTRAINT "advisory_issue_off_fk"
				FOREIGN KEY ("removed_by") REFERENCES "person"("id")
		)` + t.suffix,
	}
}

func downAdvisory(ctx context.Context, tx *sql.Tx) error {
	// An issuance points at the edition it published and an approval at the
	// edition it agreed to, so both go before the editions do.
	return dropTables(ctx, tx, "advisory_approval", "advisory_issuance",
		"advisory_edition", "advisory_issue", "advisory")
}
