package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upTeam, downTeam)
}

// A team: a named set of people that holds work.
//
// **A team holds work and grants nothing**: no role, no visibility, no
// capability. That is what lets one carry mixed clearance, which is the
// ordinary arrangement rather than a misconfiguration — a kernel team where two
// members may read undisclosed work and four may not. A team that granted
// anything would make routing work to it an access decision, and a queue could
// then only be built out of people who all see the same things.
//
// **It is assignable as a party**, the name space it shares with a person, so
// that assignment points at either through the column it already has.
// The party table is created with the person table, where the reasoning for it
// is written down.
//
// A team is retired rather than deleted, the way a person is deactivated
// rather than removed: work already routed to one has to keep resolving to
// something a screen can name.
func upTeam(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "team" (
			"id"       ` + t.id + `,
			-- The party this team is assignable as.
			"party_id" ` + t.ref + ` NOT NULL,
			-- Matched without regard to capitals and stored normalized, the
			-- way every other name people type is: the engines
			-- default differently, and a normalized value compares the same
			-- under any of them.
			"name"         ` + t.name + ` NOT NULL,
			"display_name" ` + t.free + ` NULL,
			-- Retired rather than deleted, for the reason a person is
			-- deactivated rather than removed: work already routed to it has
			-- to keep resolving to something a screen can name.
			"retired_at"   ` + t.timestamp + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "team_name_unique" UNIQUE ("name"),
			CONSTRAINT "team_party_unique" UNIQUE ("party_id"),
			CONSTRAINT "team_party_fk" FOREIGN KEY ("party_id") REFERENCES "party"("id")
		)` + t.suffix,

		// Who is on a team. Membership says nothing about what anybody may
		// read: it says where their work arrives.
		`CREATE TABLE "team_member" (
			"team_id"   ` + t.ref + ` NOT NULL,
			"person_id" ` + t.ref + ` NOT NULL,
			"added_at"  ` + t.timestamp + ` NOT NULL,
			"added_by"  ` + t.ref + ` NOT NULL,
			CONSTRAINT "team_member_pk" PRIMARY KEY ("team_id", "person_id"),
			CONSTRAINT "team_member_team_fk" FOREIGN KEY ("team_id") REFERENCES "team"("id"),
			CONSTRAINT "team_member_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "team_member_added_by_fk" FOREIGN KEY ("added_by") REFERENCES "person"("id")
		)` + t.suffix,

		// Which teams somebody is on, which is asked on every request that
		// resolves a subject and on every list narrowed to "mine".
		`CREATE INDEX "team_member_person_idx" ON "team_member" ("person_id")`,
	}

	return apply(ctx, tx, statements)
}

func downTeam(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "team_member", "team")
}
