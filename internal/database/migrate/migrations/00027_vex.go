// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upVex, downVex)
}

// What a VEX document says about a component we ship.
//
// **A third layer, never a decision**. A build's own claims are one
// layer, our decisions are another, and this is a third: what a distribution or
// an upstream security team has said. It is shown as evidence and offered as a
// prefill, and it is never applied to anything by itself — letting a third
// party's claim stand as ours would put somebody else's judgment inside a
// number we quote, which is exactly what keeping the layers apart exists to
// prevent.
//
// **What it adds over the scan is the reasoning.** The status is in the fix
// state already; what a triager otherwise types from memory, and an approver
// has no way to check, is *why* a distribution reached its answer.
//
// **Uploaded, not fetched**. The deployment is the thing with network
// access to whoever publishes, not this application — the same answer the
// scanner's vulnerability database got.
//
// The document's digest is kept so that a publisher revising a statement we
// cited can be noticed: what matters is that the ground moved under a
// dismissal somebody approved, and a digest is how that is seen at all.
func upVex(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "vex_statement" (
			"id"          ` + t.id + `,
			"product_id"  ` + t.ref + ` NOT NULL,
			-- Who published it, as the document's author names itself,
			-- normalized for matching the way every other typed name is.
			"publisher"   ` + t.name + ` NOT NULL,
			-- What the issue is called in the statement. Matched against a
			-- finding's issue by name and by alias, because which identifier a
			-- publisher chose is a preference of whichever database they
			-- consulted rather than a property of the issue.
			"vulnerability" ` + t.name + ` NOT NULL,
			-- What it points at. The package identifier where the statement
			-- carries one, and the bare name otherwise — a statement made
			-- against a source tree names something we cannot resolve to a
			-- package, and the most that can be said is that a component of
			-- that name is the one meant.
			"purl"        ` + t.free + ` NULL,
			"component"   ` + t.name + ` NOT NULL,
			-- What they said, in the format's own vocabulary, and why.
			--
			-- A name rather than a kind: the vocabulary is somebody else's and
			-- its longest word is under_investigation, which is nineteen
			-- characters against a kind's sixteen. SQLite stores it anyway and
			-- PostgreSQL refuses, so this was a four-engine failure rather
			-- than a defect anybody would have noticed developing.
			"status"        ` + t.name + ` NOT NULL,
			"justification" ` + t.name + ` NULL,
			-- The reasoning, which is the part worth having: the status is in
			-- the fix state already.
			"statement"   ` + t.text + ` NULL,
			-- The document this came from and what it hashed to, so that a
			-- revision can be noticed rather than silently replacing what an
			-- approval was granted against.
			"document"    ` + t.free + ` NOT NULL,
			"digest"      ` + t.hash + ` NOT NULL,
			"uploaded_by" ` + t.ref + ` NOT NULL,
			"uploaded_at" ` + t.timestamp + ` NOT NULL,
			-- Superseded rather than deleted when the same publisher says
			-- something else about the same thing. What an approval was
			-- granted on the strength of has to stay readable, which is the
			-- same reason a withdrawn decision is a state rather than a
			-- delete.
			"superseded_at" ` + t.timestamp + ` NULL,
			CONSTRAINT "vex_statement_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "vex_statement_by_fk" FOREIGN KEY ("uploaded_by") REFERENCES "person"("id")
		)` + t.suffix,

		// What a finding looks one up by: the product, the issue's name and the
		// component's. Only what still stands, which is the common read.
		`CREATE INDEX "vex_statement_about_idx"
			ON "vex_statement" ("product_id", "vulnerability", "component", "superseded_at")`,
	}

	return apply(ctx, tx, statements)
}

func downVex(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "vex_statement")
}
