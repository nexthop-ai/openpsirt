// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// v0.3.0's declaration of the finding table, and the indexes it makes.
// finding_component_idx is migration 12's.
//
// v0.2.0's, with when a recorded flaw was first rated. A flaw found or
// reported here is clocked from that moment on windows of its own, where
// v0.2.0 clocked it from its first recording on the windows every scanned
// finding runs on.
func findingV030(t *columnTypes) []string {
	return []string{
		// place_identity is the hashed pair of names — the component and its
		// consumer — which is what a triage decision is keyed on. It is stored
		// rather than derived so a decision can be found without walking the
		// graph of every variant it might apply to.
		`CREATE TABLE "finding" (
			"id"               ` + t.id + `,
			"target_id"        ` + t.ref + ` NOT NULL,
			"kind"             ` + t.kind + ` NOT NULL,
			-- Whether this has been disclosed. Not who may read it: every
			-- request is authenticated either way. Anything unrecognized
			-- reads as undisclosed, so a value added later cannot default
			-- rows that predate it to visible.
			"visibility"       ` + t.kind + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"component_id"     ` + t.ref + ` NOT NULL,
			"consumer_id"      ` + t.refNull + ` NULL,
			"place_identity"   ` + t.hash + ` NOT NULL,
			"fix_state"        ` + t.kind + ` NULL,
			-- A scanner reports every version that fixes an issue, and for a
			-- kernel that is a long list.
			"fixed_in"         ` + t.free + ` NULL,
			-- When the fixing version became available. "Fixed upstream
			-- fourteen months ago" is a different conversation from "fixed in
			-- 0.17.0", and it is the one that says whether an upgrade is
			-- overdue or fresh.
			"fixed_at"       ` + t.date + ` NULL,
			-- A finding the build has already argued about is marked, not
			-- dropped: one that simply stopped appearing is
			-- indistinguishable from a scanner fault.
			"suppressed_by"    ` + t.refNull + ` NULL,
			-- What is true of a finding now, alongside when it became true.
			-- A finding open for years outlives whatever record of the change
			-- was kept elsewhere, so it carries its own.
			-- How urgent this is, as one number that sorts. Written when a scan
			-- is applied rather than worked out while reading. A number
			-- computed on read would mean joining every signal it is made of
			-- for every row, on every page of every list.
			--
			-- What it was made of is kept beside it, so a position can be
			-- explained. Reading the signals back out of the packed number
			-- would work and would break silently the first time the weighting
			-- changed.
			-- Named urgency rather than rank because rank is a reserved word
			-- on one of the four engines, which accepted it everywhere else
			-- and refused the table outright there.
			"urgency"           ` + t.ref + ` NOT NULL,
			"urgency_exploited" ` + t.boolean + ` NOT NULL,
			-- Whether somebody here recorded that this product was exploited
			-- through the issue. A band of its own above the one beside it,
			-- because a feed saying the world is being attacked and a person
			-- saying we were are different facts, and only the second is an
			-- incident. The two are never read as one: a report asking which
			-- findings are exploited reads the column it means rather than
			-- the packed number, whose top bands both answer "above the
			-- line".
			"urgency_exploited_here" ` + t.boolean + ` NOT NULL,
			-- When exploitation was learned, which is what an exploited
			-- deadline is counted from.
			--
			-- Recorded rather than derived: an issue that becomes exploited
			-- six months after a finding opened has a deadline of a few days
			-- from the moment it was learned, and counting from the opening
			-- lands it in the past — a deadline nobody could have met.
			-- Nothing else in the row holds that moment, so a later recount
			-- had no base to use and quietly moved the deadline back.
			--
			-- Null where the row is not exploited, and null on one that was
			-- marked before this was recorded, which reads as "count from
			-- the opening" because there is nothing better to count from.
			"exploited_learned_at" ` + t.timestamp + ` NULL,
			"urgency_shipped"   ` + t.boolean + ` NOT NULL,
			-- What this place held before, where the version moved and the
			-- issue came with it. Present means somebody bumped this and the
			-- bump did not resolve it, which is aimed at whoever did the bump
			-- rather than at whoever triages.
			"arrived_from"     ` + t.free + ` NULL,
			-- The upstream version this place moved to, where moving is what
			-- closed the finding. The mirror of arrived_from and stored for
			-- the same reason: both versions are in hand only while the scan
			-- is being applied, and afterwards the old component is gone from
			-- the inventory that would have to be asked. Without it a release
			-- note can say a component was upgraded and never say to what.
			"moved_to"         ` + t.free + ` NULL,
			-- Who is dealing with this. Null is nobody, which is a state to be
			-- asked about rather than an absence: work nobody owns is what
			-- falls between people, and it is invisible unless it can be
			-- listed.
			--
			-- Who holds this: a **party**, which is a person or a team, in one
			-- column rather than two. Two columns are right in nine
			-- places and forgotten in the tenth, and the tenth is a list that
			-- quietly omits work.
			--
			-- No foreign key, because parties are declared after findings and
			-- one engine cannot add a constraint to a table afterwards. Worth
			-- knowing how that surfaced: with the constraint written here,
			-- SQLite created the table happily against a person table that did
			-- not exist yet, and PostgreSQL refused outright. Nothing is ever
			-- deleted — an account is deactivated and its work released, a team
			-- is retired — so what the constraint would prevent cannot arise.
			"assigned_to"      ` + t.refNull + ` NULL,
			"assigned_at"      ` + t.timestamp + ` NULL,
			-- Which standing rule placed this, where a rule did. A
			-- placement nobody can explain is one nobody can correct, and at
			-- this fan-out there will be thousands of them. No foreign key,
			-- for the reason above: the table is declared later, and a rule is
			-- retired rather than deleted.
			"routed_by"        ` + t.refNull + ` NULL,
			"last_changed_at"  ` + t.timestamp + ` NOT NULL,
			-- How the scanner reached this, and where that match came from.
			--
			-- A distribution backports fixes without moving the upstream
			-- version: busybox 1.37.0-r14 and 1.37.0-r15 are the same upstream
			-- release and one of them may carry the patch. An advisory for the
			-- package in its own ecosystem counts the release number; a
			-- comparison against a published identifier and an upstream range
			-- cannot, and fires whether or not the distribution has fixed it.
			--
			-- The source is per finding rather than per issue because one
			-- issue reached through two ecosystems has two answers, and the
			-- issue can hold only one — which is how an Alpine package came to
			-- link to Debian's tracker.
			"matched"          ` + t.kind + ` NULL,
			"matched_from"     ` + t.free + ` NULL,
			-- Which body of data answered, as the scanner names it, and the
			-- version range the match fired on. Both are evidence for the
			-- judgment the two columns above ask for rather than a second way
			-- of making it: a range naming no packaging revision, read beside
			-- a version that has one, is the argument in a line.
			--
			-- Free text, and never parsed. Deciding whether a version is
			-- inside a range needs an ordering per ecosystem, which is a
			-- different project; what these are for is a person reading them.
			--
			-- Named around the reserved word rather than quoted past it: a
			-- column called "constraint" is a syntax error the moment any
			-- query names it bare, which SQLite caught here and the other
			-- three would have caught later.
			"matched_in"       ` + t.free + ` NULL,
			"matched_range"    ` + t.free + ` NULL,
			-- When this stops being an embargo, on a finding nobody has
			-- announced. Null on a public one: it is already disclosed, and a
			-- date on it would be a deadline for something that has happened.
			--
			-- Reaching it discloses nothing. It escalates — the finding is
			-- flagged and the people who can act are told — because
			-- publishing embargoed detail on a timer eventually publishes
			-- something nobody was ready for.
			"disclose_at"      ` + t.timestamp + ` NULL,
			-- When this became true, carried on the row rather than reached
			-- through the run that opened it. Not every finding has one: a
			-- flaw somebody recorded by hand was opened by a person. Three
			-- queries reached the run for this timestamp and reached it with
			-- an inner join, which drops a finding that has no run rather
			-- than reporting it — silently, from a trend, a deadline sweep
			-- and an urgency recount at once.
			"opened_at"        ` + t.timestamp + ` NOT NULL,
			-- The run that opened it, where a run did. Null is a finding a
			-- person opened, and it is why the column stopped being required.
			"opened_run_id"    ` + t.refNull + ` NULL,
			-- When it stopped being true, and what closed it. The same
			-- separation the opening has, and for the same reason: a run is
			-- the authority on what it found, so it closes nothing a person
			-- recorded, and a finding whose closure could only be read
			-- through a run was one a person could never close at all.
			"closed_at"        ` + t.timestamp + ` NULL,
			-- When this runs out, worked out from how urgent it is and
			-- counted from when it was first seen. Null where it is on no
			-- clock at all: below the product's triage line, on a release
			-- past end of life, or already answered.
			"due_at"           ` + t.timestamp + ` NULL,
			-- The run that closed it, where a run did. Null with a closed_at
			-- set is a finding a person closed.
			"closed_run_id"    ` + t.refNull + ` NULL,
			-- Who closed it, with no constraint, for the reason assigned_to
			-- above carries: person is created by a later migration, and
			-- SQLite takes the forward reference happily while the other
			-- three refuse the table outright.
			"closed_by"        ` + t.refNull + ` NULL,
			-- Why, where a person closed it. Required of them, for the same
			-- reason moving a disclosure date is: a closure with no reason is
			-- a record saying somebody closed it and nothing else, which is
			-- the state keeping a history exists to prevent.
			"closed_note"      ` + t.text + ` NULL,
			"closed_because"   ` + t.kind + ` NULL,
			-- When a recorded flaw was first given a severity in its product,
			-- which is what its deadline counts from (REQ-33). Null on a
			-- scanned row, whose clock runs from its opening, and on a
			-- recorded flaw nobody has rated, which has no clock.
			"rated_at"         ` + t.timestamp + ` NULL,
			CONSTRAINT "finding_target_id_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "finding_vulnerability_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "finding_component_id_fk" FOREIGN KEY ("component_id") REFERENCES "component"("id"),
			CONSTRAINT "finding_consumer_id_fk" FOREIGN KEY ("consumer_id") REFERENCES "component"("id"),
			CONSTRAINT "finding_suppressed_by_fk" FOREIGN KEY ("suppressed_by") REFERENCES "suppression"("id"),
			CONSTRAINT "finding_opened_run_id_fk" FOREIGN KEY ("opened_run_id") REFERENCES "scan_run"("id"),
			CONSTRAINT "finding_closed_run_id_fk" FOREIGN KEY ("closed_run_id") REFERENCES "scan_run"("id")
		)` + t.suffix,

		`CREATE INDEX "finding_open_idx" ON "finding" ("target_id", "closed_at")`,

		// Deadlines running out, off an index rather than a scan. It leads with
		// the two columns always compared — a finding that is closed or
		// already answered is not running out of anything — so the deadline
		// itself is the range at the end of a narrow prefix.
		`CREATE INDEX "finding_due_idx" ON "finding" ("closed_at", "suppressed_by", "due_at")`,

		// Finding one issue everywhere it is present, which is what triaging
		// one vulnerability across a portfolio asks for.
		`CREATE INDEX "finding_vulnerability_idx" ON "finding" ("vulnerability_id", "closed_at")`,

		// Carrying a decision forward to the same place elsewhere, and reading
		// the findings a decision is about: a decision names an issue at a
		// place, and the place alone is not selective — one place in a switch
		// image carries every one of the kernel's 4,900 issues, so a lookup by
		// place read 4,900 rows to find the one the decision meant. With the
		// issue beside it the lookup is exact. The prefix still serves what
		// asks by place alone.
		`CREATE INDEX "finding_place_idx" ON "finding" ("place_identity", "vulnerability_id")`,

		// Both directions are asked constantly: what one person holds, and what
		// nobody holds. The second is the one that matters and the one a plain
		// index on the column would serve badly, since it is a null lookup.
		`CREATE INDEX "finding_assigned_idx" ON "finding" ("assigned_to", "closed_at")`,

		// Everything the findings list groups by, in one index, so grouping a
		// build's open findings never touches the table. The list is one row
		// per (issue, component) over every open finding in a build, ordered
		// by the worst urgency in the group, and its total is the count of
		// those groups: both read exactly these columns and nothing else. With
		// the index covering them the engine walks it and the table stays
		// cold, which is the part that scales with the image. Measured on a
		// switch operating-system image (240,945 open rows): grouping went
		// from 0.33 s to 0.05 s, and the count from 0.32 s to 0.04 s.
		//
		// The column order is the portable shape: equality columns first
		// (target, open, visibility), then the grouping key, then what the
		// aggregates read. Every engine here can answer the grouping from the
		// index alone in that order; a narrower index on urgency was tried
		// first, and it still cost a table lookup per row for the group key.
		//
		// The two exploitation flags are in it because the lists read them
		// rather than the packed number: the number carries both in bands of
		// its own and cannot say which, so every list that names one of them
		// aggregates its column, and a column outside the index is a table
		// row fetched per open finding.
		`CREATE INDEX "finding_group_idx" ON "finding" ("target_id", "closed_at", "visibility", "vulnerability_id", "component_id", "urgency", "urgency_exploited", "urgency_exploited_here")`,
	}
}
