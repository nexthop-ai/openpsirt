// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// A scan run's findings, and their subject.
//
// A vulnerability is one issue however many names it goes by. The same issue
// arrives as a national identifier from one database and an advisory
// identifier from another, and which one a scanner calls primary is a
// preference of whichever source it consulted rather than a property of the
// issue. Keying anything on that choice would lapse every decision the day a
// scanner changed its mind, so the aliases resolve to one row.
//
// A finding is a vulnerability at a place: the component, and the thing that
// directly pulled it in. One issue in a shared library is one finding per
// consumer, because different consumers use different parts of what they
// depend on.
//
// Findings are held over intervals against scan runs, the same shape the graph
// uses, for the same reason: re-scanning nightly against a database that moved
// slightly must write only what changed.
func findingStatements(t *columnTypes) []string {
	return []string{
		// An issue is filed under whichever of its names is the most widely
		// recognized, and that name folded is what makes it one row.
		`CREATE TABLE "vulnerability" (
			"id"            ` + t.id + `,
			"identifier"    ` + t.free + ` NOT NULL,
			-- The same name folded, so anything matching an issue by name
			-- compares two columns rather than a function of one.
			-- A published identifier arrives in whatever case its reporter
			-- chose, and a VEX statement arrives folded, so a comparison
			-- between them had LOWER() on the indexed side — which made the
			-- statement filter scan this whole table once per statement.
			--
			-- Unique, which is what keeps one issue one row. It was a hash of
			-- the unfolded name in a column of its own, which nothing read and
			-- which only one of the two paths that refile an issue under a
			-- better-known name maintained — so the key drifted away from the
			-- row it identified, invisibly, until a collision named a name
			-- neither issue was filed under.
			"identifier_folded" ` + t.name + ` NOT NULL,
			-- What the world says. What we say instead belongs to one
			-- product and lives in "issue_rating", because a rating is a
			-- judgment about how a component is used and two products do
			-- not use one the same way. A row here has no product, so it
			-- has nowhere to hold that.
			"severity"      ` + t.kind + ` NULL,
			-- What somebody triaging needs in front of them. There may be
			-- thousands of these and very few people, so a finding that
			-- carries its own evidence is the difference between a queue that
			-- gets worked and one that does not.
			"description"     ` + t.text + ` NULL,
			-- Where the issue is written up. Every report carries one, and for
			-- the great majority it is the only route to the patch — so it is
			-- the single most valuable thing a report gives us.
			"advisory"        ` + t.free + ` NULL,
			-- Whether somebody is known to be exploiting it, and the published
			-- estimate that they will. Together these are what separates the
			-- handful that matter from the thousands that can wait.
			"exploited"       ` + t.boolean + ` NOT NULL,
			-- Held as parts per million rather than as a fraction. Every engine
			-- spells an exact decimal differently and a float compares
			-- differently again, and this has to sort in an index.
			"likelihood_ppm"  ` + t.ref + ` NULL,
			-- Where that estimate stands among all of them, and the day it was
			-- computed for. The estimate is a thirty-day forecast recomputed
			-- daily and it legitimately falls, so the day it is about is what
			-- decides whether a report is newer than what is stored — without
			-- it, keeping the highest anybody ever published made the order
			-- answer "was ever risky" instead of "is risky".
			"likelihood_percentile_ppm" ` + t.ref + ` NULL,
			"likelihood_on"   ` + t.date + ` NULL,
			-- The severity as a number, and the statement of what it assumes.
			-- Network-reachable and unauthenticated is a different judgment
			-- from local-and-privileged at the same number, and the vector is
			-- where that shows.
			"score_centi"     ` + t.ref + ` NULL,
			"vector"          ` + t.free + ` NULL,
			-- Who published that score, which scoring system it is, and
			-- whether it is the primary rating or a secondary one. Provenance
			-- is recorded for everything else a report says — what found it,
			-- what it was matched from, what it was matched in — and the
			-- number a deadline is set from had none, so a reader asking who
			-- says 5.9 had nowhere to go.
			-- Unbounded, like everything else copied out of a report: a
			-- bounded column here means a legitimate but long value fails
			-- the whole scan that carried it, and nothing bounds what a
			-- producer writes in any of the three.
			"score_version"   ` + t.free + ` NULL,
			"score_source"    ` + t.free + ` NULL,
			"score_kind"      ` + t.free + ` NULL,
			"first_seen_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "vulnerability_folded_unique" UNIQUE ("identifier_folded")
		)` + t.suffix,

		// Every name an issue is known by, including the one it is filed
		// under. A report naming any of them finds the same row.
		`CREATE TABLE "vulnerability_reference" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"url"              ` + t.free + ` NOT NULL,
			-- What it appears to be, as far as the address reveals. A patch is
			-- the one worth telling apart: somebody deciding whether to
			-- backport rather than upgrade needs it, and hunting for it by
			-- hand is the step that does not happen when a thousand others are
			-- waiting.
			"kind"             ` + t.kind + ` NOT NULL,
			-- The hash of the address, because the address itself is longer
			-- than an index key may be on some engines.
			"url_identity"     ` + t.hash + ` NOT NULL,
			CONSTRAINT "vulnerability_reference_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "vulnerability_reference_unique" UNIQUE ("vulnerability_id", "url_identity")
		)` + t.suffix,

		// The kind of flaw, by the classification the data carries.
		//
		// A row per weakness rather than one comma-joined column, which is the
		// shape every other multi-valued attribute here has. Packed into one
		// column it was queried on anyway — the class-of-flaw filter — and the
		// only way to ask "is CWE-79 in this list" without a table is a
		// substring match, which answers CWE-79 for a search for CWE-7 unless
		// it is written as four separate patterns to respect the commas. Four
		// unindexable patterns per name asked, against every issue, where a
		// table answers with one indexed lookup.
		//
		// A report usually names the same weakness from several sources, so
		// the pair is unique: a re-scan of the same data writes nothing.
		`CREATE TABLE "vulnerability_weakness" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- Upper-cased on the way in, like every other identifier compared
			-- exactly: CWE names are written CWE-79 everywhere they are
			-- published, and a feed that shouts or whispers one should not
			-- make two rows of it.
			"cwe"              ` + t.name + ` NOT NULL,
			-- Whether this is the one the data calls the root cause.
			--
			-- Added to the migration that made the table rather than beside it,
			-- which is what a version below 1.0 promises (REQ-76). A deployment
			-- holding data has already recorded this migration as applied, so
			-- nothing here will run again and nothing will say so: the column
			-- is simply absent, and what fails is every scan, every advisory
			-- and the issue screen, each with an unknown-column error that
			-- reads like four unrelated faults. Recreate the database and
			-- re-ingest.
			--
			-- A published advisory states one weakness, and an issue is
			-- commonly classified as several. Which one is stated cannot be
			-- picked here: choosing the lowest number, or the first read, is
			-- an answer with nothing behind it. The feeds say which is primary
			-- and a person recording a flaw names theirs first, so the answer
			-- is carried rather than invented.
			"is_primary"       ` + t.boolean + ` NOT NULL,
			CONSTRAINT "vulnerability_weakness_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "vulnerability_weakness_unique" UNIQUE ("vulnerability_id", "cwe")
		)` + t.suffix,

		// The class-of-flaw filter's index: every issue of one kind.
		`CREATE INDEX "vulnerability_weakness_cwe_idx" ON "vulnerability_weakness" ("cwe")`,

		// Each published rating of an issue, one per generation of the
		// scoring scheme. A report commonly rates one issue under version 3
		// and version 4, and the two are different judgments rather than two
		// spellings of one: the screen shows the newest, and a published
		// advisory states the one its format has a field for.
		//
		// The first stated in each generation is kept whole, number and
		// vector together, so the two never come from different publishers.
		`CREATE TABLE "vulnerability_rating" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- The major version of the scheme: 2, 3 or 4. Version 3.0 and 3.1
			-- are one generation, because they share one formula and one
			-- field in every format that carries them.
			"generation"       ` + t.ref + ` NOT NULL,
			"score_centi"      ` + t.ref + ` NOT NULL,
			"vector"           ` + t.free + ` NOT NULL,
			-- Unbounded, like the three the issue carries beside its own
			-- score, and for the same reason.
			"score_version"    ` + t.free + ` NULL,
			"score_source"     ` + t.free + ` NULL,
			"score_kind"       ` + t.free + ` NULL,
			CONSTRAINT "vulnerability_rating_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "vulnerability_rating_unique" UNIQUE ("vulnerability_id", "generation")
		)` + t.suffix,

		`CREATE TABLE "vulnerability_alias" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"identifier"       ` + t.name + ` NOT NULL,
			-- Folded, for the reason the issue's own identifier is.
			"identifier_folded" ` + t.name + ` NOT NULL,
			CONSTRAINT "vulnerability_alias_unique" UNIQUE ("identifier"),
			CONSTRAINT "vulnerability_alias_vulnerability_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id")
		)` + t.suffix,

		// One execution of a scanner over one variant. Recorded whether it ran
		// here or arrived from a producer, because a report that averages two
		// scanners without saying so is worse than no report.
		`CREATE TABLE "scan_run" (
			"id"               ` + t.id + `,
			"target_id"        ` + t.ref + ` NOT NULL,
			-- What the scanner calls itself and what it was reading, both
			-- taken verbatim from its output and bounded by nothing on the
			-- way in — so they are the producer-supplied slot rather than
			-- the indexed-name one. None of the three is indexed or unique.
			"scanner"          ` + t.free + ` NOT NULL,
			"scanner_version"  ` + t.free + ` NULL,
			"database_version" ` + t.free + ` NULL,
			"ran_here"         ` + t.boolean + ` NOT NULL,
			"started_at"       ` + t.timestamp + ` NOT NULL,
			"finished_at"      ` + t.timestamp + ` NULL,
			"failure"          ` + t.text + ` NULL,
			-- What the scanner said while succeeding: a qualification on the
			-- answer rather than a reason there is none. Kept apart from the
			-- failure above because a run that warned and a run that failed
			-- are different things, and one column holding either makes them
			-- one. Told to match Go binaries with no function symbols the
			-- scanner says so and falls back to module granularity, which can
			-- report a component as affected when the vulnerable function is
			-- not linked in — that qualifies every finding of that run.
			"caution"          ` + t.text + ` NULL,
			CONSTRAINT "scan_run_target_id_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id")
		)` + t.suffix,

		// A build's own argument that something does not apply to it.
		//
		// Stored as data rather than left in the document it arrived in. A
		// nightly scan's documents are discarded once read, the vulnerability
		// scan runs after that, and it runs again on a schedule — so a claim
		// that lived only in the file would be gone by the time anything
		// needed it, and every carried patch would come back as an
		// outstanding vulnerability on the first re-scan.
		//
		// Held over intervals against scans, like the graph: a build argues
		// the same things night after night, and re-sending them must write
		// nothing.
		`CREATE TABLE "suppression" (
			"id"             ` + t.id + `,
			"target_id"      ` + t.ref + ` NOT NULL,
			"identity"       ` + t.hash + ` NOT NULL,
			"vulnerability"  ` + t.free + ` NOT NULL,
			-- The status vocabulary is the exchange format's, not ours, and
			-- its longest word today is longer than a short identifier
			-- column allows. Whatever it adds next is not ours to bound.
			"status"         ` + t.name + ` NOT NULL,
			"justification"  ` + t.free + ` NULL,
			"statement"      ` + t.text + ` NULL,
			"origin"         ` + t.kind + ` NOT NULL,
			"subject_purl"   ` + t.text + ` NULL,
			"subject_name"   ` + t.free + ` NULL,
			"opened_scan_id" ` + t.ref + ` NOT NULL,
			"closed_scan_id" ` + t.refNull + ` NULL,
			CONSTRAINT "suppression_target_id_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "suppression_opened_scan_id_fk" FOREIGN KEY ("opened_scan_id") REFERENCES "scan"("id"),
			CONSTRAINT "suppression_closed_scan_id_fk" FOREIGN KEY ("closed_scan_id") REFERENCES "scan"("id")
		)` + t.suffix,

		`CREATE INDEX "suppression_open_idx" ON "suppression" ("target_id", "closed_scan_id")`,

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
			CONSTRAINT "finding_target_id_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "finding_vulnerability_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "finding_component_id_fk" FOREIGN KEY ("component_id") REFERENCES "component"("id"),
			CONSTRAINT "finding_consumer_id_fk" FOREIGN KEY ("consumer_id") REFERENCES "component"("id"),
			CONSTRAINT "finding_suppressed_by_fk" FOREIGN KEY ("suppressed_by") REFERENCES "suppression"("id"),
			CONSTRAINT "finding_opened_run_id_fk" FOREIGN KEY ("opened_run_id") REFERENCES "scan_run"("id"),
			CONSTRAINT "finding_closed_run_id_fk" FOREIGN KEY ("closed_run_id") REFERENCES "scan_run"("id")
		)` + t.suffix,

		// Everything open now, per variant, is the query behind every screen.
		// Matching an issue by a name somebody else wrote. Both the issue's
		// own name and every name it goes by, because which of them a
		// publisher chose is a preference of whichever database they
		// consulted rather than a property of the issue.
		`CREATE INDEX "vulnerability_alias_folded_idx"
			ON "vulnerability_alias" ("identifier_folded", "vulnerability_id")`,

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
