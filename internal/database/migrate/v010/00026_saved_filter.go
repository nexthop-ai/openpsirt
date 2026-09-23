// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package v010

import (
	"context"
	"database/sql"
)

func init() {
	register(upSavedFilter, downSavedFilter)
}

// A narrowing of the findings list that somebody kept.
//
// **Personal, and nothing is shared**. No ownership, no permissions,
// no arguing about whose filter is authoritative — and nobody hesitates to save
// something half-formed. The same rule the look follows, for the same reason: a
// preference that changes nothing anybody else sees needs no policy around it.
//
// **What is kept is the query, as text.** Not a column per filter: the filters
// are the list's own and they move, and a table that mirrored them would need a
// migration every time one was added and would still be a second place where
// what a filter means is decided. A saved filter is a way back to a list, and
// the list is what knows how to read it.
//
// The consequence is deliberate and worth saying: a saved filter naming a
// filter that no longer exists simply stops narrowing by it. That is the right
// failure — a way back to a list that is slightly wider than it was, rather
// than a refusal to open a list at all.
func upSavedFilter(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "saved_filter" (
			"id"         ` + t.id + `,
			"person_id"  ` + t.ref + ` NOT NULL,
			-- What they called it, matched without regard to capitals and
			-- stored normalized like every other name people type,
			-- with the spelling they used kept beside it.
			"name"         ` + t.name + ` NOT NULL,
			"display_name" ` + t.free + ` NULL,
			-- Which product's list it narrows. A saved filter is a narrowing
			-- of one product's findings — its query names branches and
			-- variants that exist there and often nowhere else — so offering
			-- it on another product offers a filter that matches nothing and
			-- says nothing about why.
			"product_id" ` + t.ref + ` NOT NULL,
			-- The query string of the list it opens, without a leading "?".
			"query"      ` + t.text + ` NOT NULL,
			-- What a saved filter proposes about what it catches, where
			-- somebody made it a prepared claim.
			--
			-- On the saved filter rather than in a table of its own: what a
			-- rule is here is a narrowing plus what to say about what it
			-- catches, and those are one thing somebody names. A second table
			-- would make "the filter" and "the rule" two objects that have to
			-- be kept pointing at each other.
			--
			-- All four absent is an ordinary saved filter, which is most of
			-- them. None of this proposes anything by itself — picking the
			-- filter fills the decision form, and submitting it is a person's
			-- act carrying their name, because a rule that proposed a claim
			-- of its own would leave the approver as the only human judgment
			-- on it.
			"outcome"       ` + t.kind + ` NULL,
			"justification" ` + t.free + ` NULL,
			"reasoning"     ` + t.text + ` NULL,
			"defer_days"    INTEGER NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "saved_filter_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "saved_filter_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			-- One name per person, so saving over one replaces it rather than
			-- leaving two that differ in a way nothing shows.
			CONSTRAINT "saved_filter_name_unique" UNIQUE ("person_id", "product_id", "name")
		)` + t.suffix,
	}

	return apply(ctx, tx, statements)
}

func downSavedFilter(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "saved_filter")
}
