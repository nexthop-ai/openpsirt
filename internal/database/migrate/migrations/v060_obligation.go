// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// obligationV060 is the untagged release's declaration of the windows a
// deployment counts and the notices given after an attack.
//
// v0.2.0's, with the window a window counts from, the reference and the
// statement about malice a notice carries, and the places a notice named in a
// table of their own.
func obligationV060(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "obligation_window" (
			"id"    ` + t.id + `,
			-- What the window is called, as it was typed. Matched without
			-- regard to capitals through live_name, which holds it folded.
			"name"  ` + t.name + ` NOT NULL,
			-- The window's length in whole hours. Hours rather than days,
			-- because the shortest windows in force anywhere are a day.
			"length_hours" INTEGER NOT NULL,
			-- How long before the end a second notice is raised, in whole
			-- hours, where the window names one. Null is no second notice.
			"lead_hours" INTEGER NULL,
			"declared_by" ` + t.ref + ` NOT NULL,
			"declared_at" ` + t.timestamp + ` NOT NULL,
			-- Retired rather than deleted: a notice recorded against a
			-- window keeps naming it after nobody counts it any more.
			"retired_at" ` + t.timestamp + ` NULL,
			-- The name while the window is in force, and null once it is
			-- retired, so a retired name may be declared again. The same
			-- mechanism a standing record of being exploited uses.
			"live_name" ` + t.name + ` NULL,
			-- The window whose first notice this one counts from. Null
			-- counts from the moment the attack became known.
			"from_window_id" ` + t.refNull + ` NULL,
			CONSTRAINT "obligation_window_live_unique" UNIQUE ("live_name"),
			CONSTRAINT "obligation_window_declarer_fk" FOREIGN KEY ("declared_by")
				REFERENCES "person"("id"),
			CONSTRAINT "obligation_window_from_fk" FOREIGN KEY ("from_window_id")
				REFERENCES "obligation_window"("id")
		)` + t.suffix,

		`CREATE TABLE "told_outside" (
			"id"               ` + t.id + `,
			"exploited_here_id" ` + t.ref + ` NOT NULL,
			-- The window this notice answers, where the person recording it
			-- said so. Their statement rather than a computation: nothing
			-- here decides whether a notice met anything.
			"window_id" ` + t.refNull + ` NULL,
			-- Who was told: a regulator, a customer, a response team.
			"recipient" ` + t.free + ` NOT NULL,
			-- Supplied rather than taken from the clock, for the reason the
			-- moment an attack became known is.
			"told_at"   ` + t.timestamp + ` NOT NULL,
			-- What they were told.
			"said"      ` + t.text + ` NOT NULL,
			"recorded_by" ` + t.ref + ` NOT NULL,
			"recorded_at" ` + t.timestamp + ` NOT NULL,
			-- The reference the recipient gave the notice, where there was
			-- one.
			"reference" ` + t.name + ` NULL,
			-- What the notice said about whether the attack was malicious:
			-- 'yes', 'no' or 'unknown'. Null where it said nothing.
			"suspected_malicious" ` + t.kind + ` NULL,
			CONSTRAINT "told_outside_record_fk" FOREIGN KEY ("exploited_here_id")
				REFERENCES "exploited_here"("id"),
			CONSTRAINT "told_outside_window_fk" FOREIGN KEY ("window_id")
				REFERENCES "obligation_window"("id"),
			CONSTRAINT "told_outside_recorder_fk" FOREIGN KEY ("recorded_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// A record's notices, read for every record the shelf shows.
		`CREATE INDEX "told_outside_record_idx" ON "told_outside" ("exploited_here_id", "told_at")`,

		// The places a notice named, in the order they were given. Free
		// text: which places a deployment names is its own business, and
		// nothing here matches them against a list.
		`CREATE TABLE "told_place" (
			"told_id"  ` + t.ref + ` NOT NULL,
			"position" INTEGER NOT NULL,
			"place"    ` + t.name + ` NOT NULL,
			CONSTRAINT "told_place_pk" PRIMARY KEY ("told_id", "position"),
			CONSTRAINT "told_place_told_fk" FOREIGN KEY ("told_id")
				REFERENCES "told_outside"("id")
		)` + t.suffix,
	}
}
