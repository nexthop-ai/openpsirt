// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package v010

import (
	"context"
	"database/sql"
	"strconv"
)

func init() {
	register(upTrail, downTrail)
}

// What somebody changed about how this deployment works.
//
// **Who, what, before, after and when**. Three administrative levers
// silently rewrite what this tool reports: changing the deadline policy
// recomputes every open finding's deadline, raising the triage floor takes the
// deadline off everything below it, and an end-of-life date takes it off
// everything past it. None of them recorded who moved it — a setting carried
// when it changed and not by whom, a role grant when it was withdrawn and not
// who granted it.
//
// For a tool whose entire output is evidence, that is the evidence being
// movable with nothing recording that anybody moved it. It is the same gap the
// triage history closes, one layer above it.
//
// **Both values are text, and both are kept.** What a setting held before is
// not derivable afterwards, and "who raised the floor to critical" is only half
// the question somebody asks — the other half is what it was. A value that was
// unset is an absent before rather than an empty one, because "nobody had set
// it" and "somebody set it to nothing" are different acts.
func upTrail(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "admin_change" (
			"id"       ` + t.id + `,
			"at"       ` + t.timestamp + ` NOT NULL,
			-- Who. Never null: a change nobody made is a change nothing
			-- records, which is the state this table exists to end.
			"by"       ` + t.ref + ` NOT NULL,
			-- What kind of thing moved, and which one of them. The kind is
			-- what a reader filters by; the name is what they search for.
			--
			-- Wider than a name, because what is written here is composed of
			-- them: a collaborator is a product, an issue and a person, each
			-- of them a name's width, with separators between. At a name's
			-- own width the longest of those overflowed the column, which
			-- takes the act down with it on the three engines that refuse a
			-- value too long for what it is going into.
			"kind"     ` + t.kind + ` NOT NULL,
			-- Wider than a name because what is written here is composed
			-- of them, and derived from a name's own width so that moving
			-- one moves this with it. The recorder bounds what it writes
			-- to the same number, which is what keeps a composed name from
			-- ever reaching a column too small for it.
			"about"    VARCHAR(` + strconv.Itoa(composedWidth) + `) NOT NULL,
			-- What it held and what it holds. Null before means nobody had
			-- set it; null after means it was cleared.
			"was"      ` + t.text + ` NULL,
			"became"   ` + t.text + ` NULL,
			CONSTRAINT "admin_change_by_fk" FOREIGN KEY ("by") REFERENCES "person"("id")
		)` + t.suffix,

		// Three reads, three shapes. Every one of them orders by "at" and
		// none of them constrains it, so a composite led by "at" can serve
		// the ordering and nothing else — the filter behind it is applied to
		// every row walked, on a table whose own reason for existing is that
		// it only grows.
		//
		// The equality column leads and the ordering column trails, so the
		// order is still satisfied from the index.

		// The whole trail, newest first, which is the screen with no filter
		// on it.
		`CREATE INDEX "admin_change_recent_idx" ON "admin_change" ("at")`,

		// The same screen narrowed to one kind of change.
		`CREATE INDEX "admin_change_kind_idx" ON "admin_change" ("kind", "at")`,

		// What one person's own history is read by, which had no index at
		// all — so opening anybody's page read every row ever written. The
		// query asks for the exact name or for every name beginning with it
		// followed by " on ", which is left-anchored and so a range this can
		// serve on all four engines.
		`CREATE INDEX "admin_change_about_idx" ON "admin_change" ("about", "at")`,
	}

	return apply(ctx, tx, statements)
}

func downTrail(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "admin_change")
}
