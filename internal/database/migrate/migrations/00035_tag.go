// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upTag, downTag)
}

// A word somebody put on a finding.
//
// People mark work regardless. At a dozen products and thousands of
// findings they do it with nowhere to put it — inside the reasoning text,
// where nothing can filter on it and an approver reads it as part of the
// argument. A tag is where that goes instead.
//
// No fixed vocabulary, because none has been earned yet. A tag that
// becomes universal is a signal that it should be promoted to a real concept:
// "waiting on vendor" is a state the tool would want to reason about rather
// than a string somebody typed, and inventing the vocabulary first would be
// guessing at which states matter.
//
// At the grain somebody looks at: one issue, in one component, in one
// product. Not per place — a kernel flaw at sixty places is one thing somebody
// is marking — and not per build, because a tag is about the work rather than
// about a release.
func upTag(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "finding_tag" (
			"id"               ` + t.id + `,
			"product_id"       ` + t.ref + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"component_id"     ` + t.ref + ` NOT NULL,
			-- Matched without regard to capitals and stored normalized, the
			-- way every other name people type is: "Waiting" and
			-- "waiting" are one tag, and a filter that treated them as two
			-- would quietly answer half the question.
			"tag"              ` + t.name + ` NOT NULL,
			-- The spelling somebody typed, which is what is shown back.
			"typed"            ` + t.free + ` NOT NULL,
			"added_by"         ` + t.ref + ` NOT NULL,
			"added_at"         ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "finding_tag_once" UNIQUE ("product_id", "vulnerability_id", "component_id", "tag"),
			CONSTRAINT "finding_tag_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "finding_tag_issue_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "finding_tag_component_fk" FOREIGN KEY ("component_id") REFERENCES "component"("id"),
			CONSTRAINT "finding_tag_by_fk" FOREIGN KEY ("added_by") REFERENCES "person"("id")
		)` + t.suffix,

		// The list's filter: everything in a product carrying a tag.
		`CREATE INDEX "finding_tag_named_idx" ON "finding_tag" ("product_id", "tag")`,
	}

	return apply(ctx, tx, statements)
}

func downTag(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "finding_tag")
}
