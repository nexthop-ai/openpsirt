// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upCollaborator, downCollaborator)
}

// One person brought into one undisclosed case.
//
// The grant is on the pair of product and issue, not on the product: a
// collaborator sees that issue everywhere it sits in that product and nothing
// else — not the rest of the embargo list, and not a count of it. The case it
// exists for is the kernel engineer who normally sees only public findings and
// is needed on one embargoed kernel flaw.
//
// It grants reading and arguing, never approving. Two collaborators could
// otherwise satisfy the two people a dismissal on an embargoed finding asks for
// with nobody accountable for the product involved, which is the rule met in
// form and defeated in substance. Approval stays with the pool that already
// held it, so nothing here records a capability.
//
// Withdrawn rather than deleted, like every other grant: who could see an
// embargoed case, and when, is exactly the question asked afterwards. The open
// row carries the pair again so that "one live grant per person per case" is
// enforced by the database rather than by a check somebody remembers — nulls do
// not collide in a unique index on any of the four engines, which is what makes
// a withdrawn row not block a fresh grant.
func upCollaborator(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "case_collaborator" (
			"id"              ` + t.id + `,
			"product_id"      ` + t.ref + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"person_id"       ` + t.ref + ` NOT NULL,
			-- Who brought them in. Adding somebody to a case is an access
			-- change and is recorded as one; this is the row's own copy of
			-- the actor, beside the administration trail's.
			"added_by"        ` + t.ref + ` NOT NULL,
			"added_at"        ` + t.timestamp + ` NOT NULL,
			"removed_by"      ` + t.refNull + ` NULL,
			"removed_at"      ` + t.timestamp + ` NULL,
			-- The pair again while the grant stands, null once it is
			-- withdrawn. A column rather than a partial index, because two of
			-- the four engines have no partial index and the unique index over
			-- three columns is the portable spelling of the same rule.
			"live_person_id"  ` + t.refNull + ` NULL,
			CONSTRAINT "case_collaborator_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "case_collaborator_issue_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "case_collaborator_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "case_collaborator_by_fk" FOREIGN KEY ("added_by") REFERENCES "person"("id")
		)` + t.suffix,

		`CREATE UNIQUE INDEX "case_collaborator_live_idx"
			ON "case_collaborator" ("product_id", "vulnerability_id", "live_person_id")`,

		// The key a subject is resolved with: every case one person is on, read
		// at sign-in beside their roles.
		`CREATE INDEX "case_collaborator_person_idx"
			ON "case_collaborator" ("person_id", "live_person_id")`,
	}

	return apply(ctx, tx, statements)
}

func downCollaborator(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "case_collaborator")
}
