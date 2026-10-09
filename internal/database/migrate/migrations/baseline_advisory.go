// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// The advisory, the issues it covers, what it says, who agreed to it, and
// that it went out.
//
// An advisory is a record of its own under an identifier this deployment
// mints, rather than a document derived from one product and one issue. The
// standard carries vulnerabilities as an array and means the tracking
// identifier to be the publisher's own name for the document, so a key made of
// a product and an issue cannot express a document about two of them and hands
// out somebody else's name for one of them. Several embargoed flaws released
// together is one document on one date, which that key has no way to say.
//
// An issuance is a fact about a moment rather than a derived value. What was
// published on a date cannot be worked out again once the record it was
// generated from has moved on — a release is added, a decision is revised, a
// fix lands — so if it is not written down when it happens it is gone.
//
// Without it a second advisory cannot carry a revision history or increment
// its version, and both are things CSAF validators check. A document that
// fails validation is one a customer's tooling drops, which is the failure
// that looks like nothing happening.
//
// An edition is what the advisory says at a point, and an approval names one
// of them. The text a document carries is the company speaking, so a second
// person reads it before it leaves — and they read particular words, which is
// why the agreement names the edition rather than the advisory. Editing opens
// a new edition and takes back every approval standing on the one it replaced.
//
// The document that went out is kept beside the act. Whoever publishes owns
// the published advisory; what is held here is the bytes this deployment
// generated and handed over, which is the only copy of a moment that has
// passed. The digest beside it is over the part of those bytes that says what
// the document states, so "is what is published still what we generate" stays
// a question with a yes or no.
func advisoryBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "advisory" (
			"id"         ` + t.id + `,
			-- The name a reader cites the document by, minted here: a prefix
			-- the deployment configures, the year, and a number within it.
			-- It belongs to the document rather than to whichever issue was
			-- first, and a revision keeps it.
			"identifier" ` + t.name + ` NOT NULL,
			-- The same name folded, which is what uniqueness and lookup are
			-- asked of. A name people type is matched without regard to
			-- capitals, and the engines disagree about how a comparison
			-- folds, so the folded value is stored rather than the
			-- comparison being asked to fold.
			"identifier_folded" ` + t.name + ` NOT NULL,
			-- The two parts the identifier was minted from, kept as numbers.
			-- Minting asks for the highest number in the current year, and
			-- taking that out of the identifier would mean parsing a string
			-- four engines parse differently. The identifier stays the name
			-- that was given, so a prefix changed later renames nothing.
			"minted_year"      ` + t.ref + ` NOT NULL,
			"mint_number"      ` + t.ref + ` NOT NULL,
			-- What the advisory says as it stands. An approval points at one
			-- edition rather than at the advisory, so this moving is exactly
			-- what withdraws an approval.
			--
			-- No foreign key: the table it points at is declared below and
			-- points back here, and neither engine that enforces order during
			-- a bulk delete would accept the cycle.
			"edition_id" ` + t.refNull + ` NULL,
			-- The moment the document dates itself from, frozen when the
			-- advisory first went out. Until then it is the earliest
			-- recording among the flaws it covers, worked out each time the
			-- document is generated; naming an older flaw afterwards would
			-- otherwise move a published document's first-release date, and
			-- with it the year folder a reader already found it in.
			"released_from" ` + t.timestamp + ` NULL,
			"minted_at"  ` + t.timestamp + ` NOT NULL,
			"minted_by"  ` + t.ref + ` NOT NULL,
			CONSTRAINT "advisory_identifier_once" UNIQUE ("identifier_folded"),
			CONSTRAINT "advisory_number_once" UNIQUE ("minted_year", "mint_number"),
			CONSTRAINT "advisory_by_fk" FOREIGN KEY ("minted_by") REFERENCES "person"("id")
		)` + t.suffix,

		`CREATE TABLE "advisory_edition" (
			"id"          ` + t.id + `,
			"advisory_id" ` + t.ref + ` NOT NULL,
			-- Which edition this is, counting from one. An approval names an
			-- edition, so the number is what a reader of the record follows
			-- to find out what somebody agreed to.
			"ordinal"     ` + t.ref + ` NOT NULL,
			-- What somebody titled it. The document falls back to naming the
			-- issues it covers, so this is absent until anybody says
			-- otherwise.
			"title"       ` + t.free + ` NULL,
			"written_by"  ` + t.ref + ` NOT NULL,
			"written_at"  ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "advisory_edition_once" UNIQUE ("advisory_id", "ordinal"),
			CONSTRAINT "advisory_edition_advisory_fk"
				FOREIGN KEY ("advisory_id") REFERENCES "advisory"("id"),
			CONSTRAINT "advisory_edition_by_fk"
				FOREIGN KEY ("written_by") REFERENCES "person"("id")
		)` + t.suffix,

		// The agreeing person, and what exactly they agreed to.
		//
		// Kept rather than reduced to a flag on the advisory, because an
		// approval that was later withdrawn is part of the record: it says a
		// second person did once agree, and to which edition.
		`CREATE TABLE "advisory_approval" (
			"id"           ` + t.id + `,
			"advisory_id"  ` + t.ref + ` NOT NULL,
			-- The edition agreed to, not the advisory. A second pair of eyes
			-- reads particular words; an approval that floated free of them
			-- would still be standing after somebody rewrote them, and
			-- nothing would report that.
			"edition_id"   ` + t.ref + ` NOT NULL,
			"approved_by"  ` + t.ref + ` NOT NULL,
			"approved_at"  ` + t.timestamp + ` NOT NULL,
			-- Taken back, by whom, which is not who gave it. An edit
			-- withdraws every approval standing on what it replaced, and the
			-- person who edited is the person who took the agreement back.
			"withdrawn_at" ` + t.timestamp + ` NULL,
			"withdrawn_by" ` + t.refNull + ` NULL,
			CONSTRAINT "advisory_approval_advisory_fk"
				FOREIGN KEY ("advisory_id") REFERENCES "advisory"("id"),
			CONSTRAINT "advisory_approval_edition_fk"
				FOREIGN KEY ("edition_id") REFERENCES "advisory_edition"("id"),
			CONSTRAINT "advisory_approval_by_fk"
				FOREIGN KEY ("approved_by") REFERENCES "person"("id"),
			CONSTRAINT "advisory_approval_back_fk"
				FOREIGN KEY ("withdrawn_by") REFERENCES "person"("id")
		)` + t.suffix,

		// On the edition, which is what the read asks for: every document
		// generated wants the agreements standing on what the advisory says
		// now. The advisory's own column is looked up only when an edit takes
		// agreements back, and the table holds an advisory a fortnight.
		`CREATE INDEX "advisory_approval_edition_idx" ON "advisory_approval" ("edition_id")`,

		`CREATE TABLE "advisory_issuance" (
			"id"          ` + t.id + `,
			-- Keyed on the advisory, which is what makes a revision of a
			-- document covering two issues one record rather than two.
			"advisory_id" ` + t.ref + ` NOT NULL,
			-- Which issuance this is, counting from one. It is what the
			-- document's version says, and a validator checks that a revised
			-- document carries a higher one than the last.
			"ordinal"     ` + t.ref + ` NOT NULL,
			-- The edition that went out, which is a fact about a moment. The
			-- advisory moves on to later editions and what was published
			-- does not, so asked of the advisory today a record of what went
			-- out in March answers with June's title.
			"edition_id"  ` + t.ref + ` NOT NULL,
			-- What went out, and the same bytes hashed.
			--
			-- The document is kept because it cannot be worked out again: a
			-- release is added, a decision is revised, a fix lands, and what
			-- would be generated today is a different document. A directory
			-- of published advisories serves the bytes that went out, and
			-- regenerating them would move a file whose date says it has not
			-- moved.
			--
			-- The digest is over the part of those bytes that says what the
			-- document states, so it answers "is what is published still
			-- what we generated" while the document answers "what was
			-- published". Both are written from the one document in the one
			-- statement.
			--
			-- Null on an issuance a release before v0.2.0 recorded, which
			-- kept the digest and not the bytes.
			"document"    ` + t.free + ` NULL,
			"digest"      ` + t.hash + ` NOT NULL,
			-- What somebody wants said about this revision, where they said
			-- anything. A revision history whose every entry reads the same is
			-- one nobody reads.
			"summary"     ` + t.free + ` NULL,
			"issued_by"   ` + t.ref + ` NOT NULL,
			"issued_at"   ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "advisory_issuance_once" UNIQUE ("advisory_id", "ordinal"),
			CONSTRAINT "advisory_issuance_advisory_fk"
				FOREIGN KEY ("advisory_id") REFERENCES "advisory"("id"),
			CONSTRAINT "advisory_issuance_edition_fk"
				FOREIGN KEY ("edition_id") REFERENCES "advisory_edition"("id"),
			CONSTRAINT "advisory_issuance_by_fk" FOREIGN KEY ("issued_by") REFERENCES "person"("id")
		)` + t.suffix,

		`CREATE TABLE "advisory_issue" (
			"id"               ` + t.id + `,
			"advisory_id"      ` + t.ref + ` NOT NULL,
			-- The product this issue is covered in. An issue in two products
			-- is two entries: the releases that carry it differ, and a status
			-- is stated about releases.
			"product_id"       ` + t.ref + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"added_at"         ` + t.timestamp + ` NOT NULL,
			"added_by"         ` + t.ref + ` NOT NULL,
			-- Taken back off, by whom. The row stays so that the act has
			-- somewhere to be written: deleted, who removed an issue from an
			-- advisory is a question nothing answers. Adding it again revives
			-- this row rather than writing a second one, which is what keeps
			-- the pair unique.
			"removed_at"       ` + t.timestamp + ` NULL,
			"removed_by"       ` + t.refNull + ` NULL,
			CONSTRAINT "advisory_issue_once"
				UNIQUE ("advisory_id", "product_id", "vulnerability_id"),
			CONSTRAINT "advisory_issue_advisory_fk"
				FOREIGN KEY ("advisory_id") REFERENCES "advisory"("id"),
			CONSTRAINT "advisory_issue_product_fk"
				FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "advisory_issue_issue_fk"
				FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "advisory_issue_by_fk" FOREIGN KEY ("added_by") REFERENCES "person"("id"),
			CONSTRAINT "advisory_issue_off_fk"
				FOREIGN KEY ("removed_by") REFERENCES "person"("id")
		)` + t.suffix,
	}
}

// advisoryJudgmentBaseline declares a release an advisory marks affected, and
// what an agreement to an advisory saw about each release. An advisory states a
// release covered by approved decisions that the flaw does not apply as known
// not affected.
func advisoryJudgmentBaseline(t *columnTypes) []string {
	return []string{
		// A release the person preparing an advisory marks affected whatever
		// its decisions say. Part of what the advisory says, so setting one
		// and clearing one each open an edition.
		`CREATE TABLE "advisory_override" (
			"id"               ` + t.id + `,
			"advisory_id"      ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- The release, as the stream and the variant it was built from.
			"stream_id"        ` + t.ref + ` NOT NULL,
			"variant_id"       ` + t.ref + ` NOT NULL,
			"set_at"           ` + t.timestamp + ` NOT NULL,
			"set_by"           ` + t.ref + ` NOT NULL,
			-- Cleared, by whom. The row stays so that the act has somewhere to
			-- be written, and marking the release again revives it, which is
			-- what keeps the release marked once.
			"removed_at"       ` + t.timestamp + ` NULL,
			"removed_by"       ` + t.refNull + ` NULL,
			CONSTRAINT "advisory_override_once" UNIQUE
				("advisory_id", "product_id", "vulnerability_id", "stream_id", "variant_id"),
			CONSTRAINT "advisory_override_advisory_fk"
				FOREIGN KEY ("advisory_id") REFERENCES "advisory"("id"),
			CONSTRAINT "advisory_override_product_fk"
				FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "advisory_override_vulnerability_fk"
				FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "advisory_override_stream_fk"
				FOREIGN KEY ("stream_id") REFERENCES "stream"("id"),
			CONSTRAINT "advisory_override_variant_fk"
				FOREIGN KEY ("variant_id") REFERENCES "variant"("id"),
			CONSTRAINT "advisory_override_by_fk"
				FOREIGN KEY ("set_by") REFERENCES "person"("id"),
			CONSTRAINT "advisory_override_back_fk"
				FOREIGN KEY ("removed_by") REFERENCES "person"("id")
		)` + t.suffix,

		// What each release stood at when a second person agreed to the
		// advisory. A fact about a moment: a decision approved or lapsing
		// afterwards moves a release's status without withdrawing the
		// agreement, and this is what says it moved since.
		`CREATE TABLE "advisory_agreed_status" (
			"id"               ` + t.id + `,
			"approval_id"      ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"stream_id"        ` + t.ref + ` NOT NULL,
			"variant_id"       ` + t.ref + ` NOT NULL,
			-- The standard's word for it: known_affected, known_not_affected
			-- or fixed.
			"status"           ` + t.name + ` NOT NULL,
			CONSTRAINT "advisory_agreed_status_approval_fk"
				FOREIGN KEY ("approval_id") REFERENCES "advisory_approval"("id"),
			CONSTRAINT "advisory_agreed_status_product_fk"
				FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "advisory_agreed_status_vulnerability_fk"
				FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "advisory_agreed_status_stream_fk"
				FOREIGN KEY ("stream_id") REFERENCES "stream"("id"),
			CONSTRAINT "advisory_agreed_status_variant_fk"
				FOREIGN KEY ("variant_id") REFERENCES "variant"("id")
		)` + t.suffix,

		// On the agreement, which is what the read asks for: the statuses
		// the agreements standing on what the advisory says now saw.
		`CREATE INDEX "advisory_agreed_status_approval_idx" ON "advisory_agreed_status" ("approval_id")`,
	}
}

// The suppliers whose published advisories this deployment fetches.
//
// A supplier's security advisory already arrives by upload, which is somebody
// deciding that one document is worth reading. A supplier publishes hundreds a
// year, and the ones about a component a build here ships are not knowable in
// advance, so the deliberate act is choosing the publisher rather than choosing
// the document.
//
// Per product, because that is what a claim is recorded against. A supplier
// feeding two products is two rows, and each supersedes only its own product's
// claims — which is what keeps withdrawing one from touching the other.
//
// Named as well as addressed, for the reason a destination is: the name is what
// a screen and a log line call it, and an address a supplier moves is a change
// to a row rather than a different supplier.
func advisorySourceBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "advisory_source" (
			"id"           ` + t.id + `,
			"product_id"   ` + t.ref + ` NOT NULL,
			-- What it is called, lowered, which is what a name typed here is
			-- matched by. Normalizing the stored value rather than comparing
			-- loosely is what makes every engine agree without any of them
			-- being asked to.
			"name"         ` + t.name + ` NOT NULL,
			-- The spelling somebody typed, which is what gets shown back.
			"display_name" ` + t.name + ` NOT NULL,
			-- Where the supplier describes what they publish: the CSAF
			-- provider description, which names the feeds the documents are
			-- listed in. An address rather than a document, because a
			-- publisher issues one advisory per issue and a list of them is
			-- the only thing that stays at one address.
			"url"          ` + t.free + ` NOT NULL,
			-- How far through what a publisher lists this source has been
			-- read: the moment, and the address that moment was last read at.
			--
			-- A pair rather than a moment, because a publisher stamps a batch
			-- of documents with one moment and a date-only stamp gives a whole
			-- day the same one. Read as a moment alone, a cycle that stopped
			-- inside such a group would leave the mark on that moment and skip
			-- the rest of the group for ever.
			--
			-- The address is kept as its digest, so the comparison that orders
			-- two marks is over lower-case hexadecimal. Every engine orders
			-- those the same way whatever its collation, which a comparison
			-- over addresses themselves does not.
			"caught_up_to"   ` + t.timestamp + ` NULL,
			"caught_up_mark" ` + t.hash + ` NULL,
			-- When a pass last tried this supplier, when one last succeeded,
			-- and what stopped the last one. Two moments rather than one: an
			-- attempt that failed still happened, so a single moment reads as
			-- a supplier answering fine right up to the failure it is
			-- reporting — and "unreachable for a week" is only visible as the
			-- gap between them.
			"fetched_at"   ` + t.timestamp + ` NULL,
			"reached_at"   ` + t.timestamp + ` NULL,
			"failed"       ` + t.free + ` NULL,
			"created_by"   ` + t.ref + ` NOT NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			-- Retired rather than deleted, like every other configured thing:
			-- what was taken from where is a question asked afterwards, and
			-- the claims already recorded name this publisher.
			"retired_at"   ` + t.timestamp + ` NULL,
			CONSTRAINT "advisory_source_named_once" UNIQUE ("product_id", "name"),
			CONSTRAINT "advisory_source_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id"),
			CONSTRAINT "advisory_source_by_fk" FOREIGN KEY ("created_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// What the pass reads: every source still configured, across every
		// product, the one longest untried first. Without it that is a scan of
		// the table on every cycle, over a table whose size is the number of
		// products an estate holds times the publishers each reads from.
		`CREATE INDEX "advisory_source_due_idx" ON "advisory_source"
			("retired_at", "fetched_at")`,
	}
}

// What a third party has said about a component we ship.
//
// A third layer, never a decision. A build's own claims are one
// layer, our decisions are another, and this is a third: what a distribution or
// an upstream security team has said. It is shown as evidence and offered as a
// prefill, and it is never applied to anything by itself — letting a third
// party's claim stand as ours would put somebody else's judgment inside a
// number we quote, which is exactly what keeping the layers apart exists to
// prevent.
//
// Two kinds of document arrive here. A VEX document is a publisher's whole
// statement set, so a later one from the same publisher replaces it. A
// security advisory is one announcement about one issue, of which a publisher
// issues hundreds, so it is replaced by the name the publisher gave it and
// nothing else.
//
// It adds the reasoning over the scan. The status is in the fix
// state already; what a triager otherwise types from memory, and an approver
// has no way to check, is *why* a distribution reached its answer.
//
// Uploaded, not fetched. The deployment is the thing with network
// access to whoever publishes, not this application — the same answer the
// scanner's vulnerability database got.
//
// The document's digest is kept so that a publisher revising a statement we
// cited can be noticed: what matters is that the ground moved under a
// dismissal somebody approved, and a digest is how that is seen at all.
func vexBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "vex_statement" (
			"id"          ` + t.id + `,
			"product_id"  ` + t.ref + ` NOT NULL,
			-- Who published it, as the document's author names itself,
			-- normalized for matching the way every other typed name is.
			"publisher"   ` + t.name + ` NOT NULL,
			-- Which kind of document carried it, and the name the publisher
			-- gave that document where it carries one.
			--
			-- Together they are what a later upload replaces. A publisher's
			-- statement set replaces their previous statement set; one of
			-- their advisories replaces the same advisory and leaves the rest
			-- of what they have published standing. Keyed on the publisher
			-- alone, every advisory from a publisher would set aside every
			-- other one the moment the next arrived.
			-- A kind rather than a name: this vocabulary is ours and its
			-- longest word is eight characters, unlike the status below.
			"source"      ` + t.kind + ` NOT NULL,
			-- Empty where the document carries no name of its own, which a
			-- statement set does not. A value rather than an absence, so the
			-- key is compared the same way on every engine.
			"document_id" ` + t.name + ` NOT NULL,
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
			-- Which version the claim was made about, where the document
			-- stated one. Inside the package identifier for a publisher that
			-- states packages, and as the branch the product sits in for one
			-- that states products and no identifier at all.
			--
			-- Stored rather than read back out of the identifier, because for
			-- that second kind there is no identifier to read it out of — and
			-- a status shown without it says the opposite of what it means
			-- against a component at another version.
			"about"       ` + t.name + ` NOT NULL,
			-- What they said, in the format's own vocabulary, and why.
			--
			-- A name rather than a kind: the vocabulary is somebody else's and
			-- its longest word is under_investigation, which is nineteen
			-- characters against a kind's sixteen. SQLite stores a longer
			-- value anyway and PostgreSQL refuses it.
			"status"        ` + t.name + ` NOT NULL,
			"justification" ` + t.name + ` NULL,
			-- The reasoning, which is the part worth having: the status is in
			-- the fix state already.
			"statement"   ` + t.text + ` NULL,
			-- The file it arrived as and what it hashed to, so that a
			-- revision can be noticed rather than silently replacing what an
			-- approval was granted against. A file name is what a client
			-- called it rather than what it is, which is why it identifies
			-- nothing.
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

		// The key a finding looks one up by: the product, the issue's name and
		// the component's. Only what still stands, which is the common read.
		`CREATE INDEX "vex_statement_about_idx"
			ON "vex_statement" ("product_id", "vulnerability", "component", "superseded_at")`,

		// The key an upload sets aside what it replaces by, and asks what it
		// already holds by. The index above shares only its first column, so
		// without this every upload reads every statement row the product
		// holds — and on the two engines whose default isolation locks what a
		// write scanned, the scan's breadth is the lock's breadth, against
		// triagers reading at the same time. A publisher issues one statement
		// set and hundreds of advisories, so that read is the ordinary
		// operation rather than a rare one.
		`CREATE INDEX "vex_statement_from_idx"
			ON "vex_statement" ("product_id", "publisher", "source", "document_id", "superseded_at")`,
	}
}

// A generated VEX document going out.
//
// Beside the imported statement of somebody else's document, and the opposite
// direction: this is a document written here, about one build, that somebody
// sent to a customer.
//
// The document is assembled from what stands about the build at the moment it
// is asked for, so it holds no history of its own. A reader keeps documents by
// the identifier they carry, which means the identifier has to stay still
// while the version moves — that is what makes two documents revisions of one
// thing rather than two documents that happen to describe one build. Without a
// record of the act there is nothing for the version to count.
//
// What was published on a date cannot be worked out again once a decision is
// revised, a claim is withdrawn or a scan closes a finding, so the act is
// recorded when it happens, with the bytes that went out. The digest is what
// makes "is what is published still what we would generate" a question with a
// yes or no.
func vexIssuanceBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "vex_issuance" (
			"id"        ` + t.id + `,
			-- The build the document is about, which is what its identifier
			-- names: one release built one way. A document about a second
			-- build is a different document rather than a revision of this
			-- one.
			"target_id" ` + t.ref + ` NOT NULL,
			-- Which issuance this is, counting from one. The document
			-- generated now is one past it, the way the next advisory is one
			-- past what has gone out.
			"ordinal"   ` + t.ref + ` NOT NULL,
			-- What went out, hashed over what the document says. The parts
			-- that move for reasons other than the content are left out, so
			-- that a document regenerated unchanged hashes the same.
			"digest"    ` + t.hash + ` NOT NULL,
			-- The bytes that went out, carrying the ordinal above as their
			-- version. Generated in the write that takes the ordinal, so the
			-- number a document states and the number it is recorded under
			-- are one number.
			"document"  ` + t.free + ` NOT NULL,
			"issued_by" ` + t.ref + ` NOT NULL,
			"issued_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "vex_issuance_once" UNIQUE ("target_id", "ordinal"),
			CONSTRAINT "vex_issuance_target_fk"
				FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "vex_issuance_by_fk" FOREIGN KEY ("issued_by") REFERENCES "person"("id")
		)` + t.suffix,
	}
}
