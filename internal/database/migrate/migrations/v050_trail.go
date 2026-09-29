// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"strconv"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// trailV050 is v0.5.0's declaration of the administrative trail.
func trailV050(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "admin_change" (
			"id"       ` + t.id + `,
			"at"       ` + t.timestamp + ` NOT NULL,
			-- Who, where a person made it. Null where the actor is
			-- configuration, a merge or an upgrade, which are no person.
			"by"       ` + t.ref + ` NULL,
			-- What kind of thing moved, and which one of them. The kind is
			-- what a reader filters by; the name is what they search for.
			"kind"     ` + t.kind + ` NOT NULL,
			-- Wider than a name because what is written here is composed
			-- of them, and derived from a name's own width so that moving
			-- one moves this with it. The recorder bounds what it writes
			-- to the same number, which is what keeps a composed name from
			-- ever reaching a column too small for it.
			"about"    VARCHAR(` + strconv.Itoa(database.ComposedWidth) + `) NOT NULL,
			-- What it held and what it holds. Null before means nobody had
			-- set it; null after means it was cleared.
			"was"      ` + t.text + ` NULL,
			"became"   ` + t.text + ` NULL,
			-- Who acted: a person, named in "by"; the deployment's startup
			-- configuration, which names administrators; a scan merging two
			-- issues; or an upgrade withdrawing a key or a token whose name
			-- another holds. Never absent: a change nobody made is a change nothing
			-- records.
			"actor"    ` + t.kind + ` NOT NULL,
			CONSTRAINT "admin_change_by_fk" FOREIGN KEY ("by") REFERENCES "person"("id")
		)` + t.suffix,

		`CREATE INDEX "admin_change_recent_idx" ON "admin_change" ("at")`,
		`CREATE INDEX "admin_change_kind_idx" ON "admin_change" ("kind", "at")`,
		`CREATE INDEX "admin_change_about_idx" ON "admin_change" ("about", "at")`,
	}
}
