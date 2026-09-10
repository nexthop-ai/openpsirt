package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upTriage, downTriage)
}

// What people decide about findings.
//
// The key is the whole design. A decision is a claim about a combination of
// code rather than about the release it was made in, so it is keyed on what
// that combination is: the product, the issue, the place, and the upstream
// versions of the component and of the thing that pulls it in. Nothing in the
// key names a release, which is what makes a later release inherit a decision
// by looking it up rather than by copying it — no syncing, and nothing to
// drift.
//
// The same key is what makes expiry work without a mechanism of its own. When
// a version moves, the key a finding computes stops matching the key a
// decision was stored under, and the decision simply no longer applies. That
// is why identity here is structural and expiry is version-based and neither
// borrows from the other: overlapping them is how a bump at the top of a build
// invalidates a judgment made about a leaf.
func upTriage(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		// One proposer's action, which is the unit an approver works
		// at.
		//
		// A judgment about a finding writes one decision per place,
		// and a judgment about many issues writes one per issue and
		// per place. The records underneath stay that fine, because
		// each is keyed and lapses on its own — but the thing a second
		// person reads and agrees to is the action, not its rows.
		// Without an identity for the action the review queue was one
		// card per row, and a finding at sixty-two places was
		// sixty-two identical cards.
		//
		// derived_from names the claim this one came from: the
		// approved claim an extension carries to a new issue, or the
		// claim an approver set some rows aside from when agreeing to
		// the rest . Either way the link is what makes "how many
		// claims rest on this argument" answerable.
		`CREATE TABLE "claim" (
			"id"           ` + t.id + `,
			"kind"         ` + t.kind + ` NOT NULL,
			"proposed_by"  ` + t.ref + ` NOT NULL,
			"proposed_at"  ` + t.timestamp + ` NOT NULL,
			"derived_from" ` + t.refNull + ` NULL,
			-- How the set was narrowed, for a claim recorded over many issues.
			-- Copied from the action rather than read off a row, so a claim
			-- whose rows were all set aside still says how it was found.
			"selected_by"  ` + t.free + ` NULL,
			-- **What the claim says.** One act is one argument, so the argument
			-- is here and not once per row underneath. It was on the row, and a
			-- judgment reaching forty-four places was forty-four copies of one
			-- sentence that could each be revised on their own: revising one
			-- returned that row to the queue and left the other forty-three
			-- saying the old thing while the claim read as agreed.
			--
			-- Every one of these was constant across every row of every claim
			-- in the measured deployment. Nothing has ever produced a claim
			-- whose rows differ in any of them.
			"outcome"       ` + t.kind + ` NOT NULL,
			-- Only "not applicable" carries one, and it is required there: the
			-- claim is that something does not affect us, and which of the
			-- recognized reasons it is *is* the claim.
			"justification" ` + t.free + ` NULL,
			-- Set only for a deferral, which is the one outcome that expires
			-- on a date rather than on the code changing.
			"deferred_until" ` + t.date + ` NULL,
			-- Set only where the claim is that the fix is already here: the
			-- package version whoever packages this states it arrived in.
			-- Required there, because that outcome asserts a fact somebody can
			-- check against the packager's own record rather than a judgment,
			-- and one with nothing to check is the one to be most careful of.
			--
			-- Free text rather than a bounded version column: it is never
			-- matched on and never compared, only read by a person.
			"fixed_version"  ` + t.free + ` NULL,
			-- Set only for the two outcomes that promise to act: when the work
			-- will be done, and the version an upgrade moves to.
			--
			-- A deferral's date says when somebody will look again; this one
			-- says when the thing will have happened, after which the scans
			-- say whether it did. Two columns rather than one reused, because
			-- a report asking "what is committed and overdue" must not have to
			-- know which outcome a date belongs to.
			"committed_to"   ` + t.date + ` NULL,
			"upgrade_to"     ` + t.free + ` NULL,
			-- What the current reasoning is. An approval points at one
			-- revision rather than at the claim, so this moving is exactly
			-- what withdraws an approval.
			--
			-- No foreign key: the table it points at is declared below and
			-- points back here, and neither engine that enforces order during
			-- a bulk delete would accept the cycle.
			"revision_id"    ` + t.refNull + ` NULL,
			CONSTRAINT "claim_proposer_fk" FOREIGN KEY ("proposed_by") REFERENCES "person"("id"),
			CONSTRAINT "claim_derived_fk" FOREIGN KEY ("derived_from") REFERENCES "claim"("id")
		)` + t.suffix,

		`CREATE INDEX "claim_derived_idx" ON "claim" ("derived_from")`,

		// One claim about one combination of code.
		//
		// place_identity is the structural half — the hashed pair of
		// names, no versions anywhere in it. The two version columns
		// are the expiry half. Keeping them in separate columns rather
		// than folded into one key is what lets the structural half be
		// looked up on its own, which is how a decision that has
		// lapsed is found again in order to offer its reasoning back
		// to whoever has to re-make it.
		//
		// consumer_upstream_version is absent where the thing above is
		// the product itself, which is excluded from identity and from
		// expiry because its version changes on every build.
		`CREATE TABLE "decision" (
			"id"                         ` + t.id + `,
			-- The VEX statement this was started from, where one was.
			-- A citation rather than an application: what the
			-- statement said is never our judgment, and what this records is
			-- that somebody read it before making theirs — which is what makes
			-- "the ground moved under an approved dismissal" a thing anything
			-- can notice. No foreign key, for the reason assigned_to has none:
			-- the table is declared later, and nothing is ever deleted from it.
			"from_statement_id"          ` + t.refNull + ` NULL,
			-- The action this row was written by. Every decision belongs to
			-- one; the claim is what the queue lists and what is approved.
			"claim_id"                   ` + t.ref + ` NOT NULL,
			"product_id"                 ` + t.ref + ` NOT NULL,
			"vulnerability_id"           ` + t.ref + ` NOT NULL,
			"place_identity"             ` + t.hash + ` NOT NULL,
			-- The finding's, carried here so that who may reach a decision is
			-- answered by the row rather than by whoever built the query. A
			-- finding nobody has disclosed is one only a private triager may
			-- argue about, and that has to hold for a report and an export as
			-- much as for reading one.
			"visibility"                 ` + t.kind + ` NOT NULL,
			"component_upstream_version" ` + t.name + ` NULL,
			"consumer_upstream_version"  ` + t.name + ` NULL,
			-- How bad this was judged to be when the claim was made, in
			-- hundredths. Kept with the decision rather than read from the
			-- issue later, because the question a re-affirmation asks is
			-- whether severity has risen *since* — and an issue's severity is
			-- rewritten in place as reports revise it, so reading it now would
			-- always compare a number against itself.
			"severity_centi"             ` + t.ref + ` NULL,
			-- Whether a second person has to agree before this takes effect.
			-- Recorded rather than worked out on each read: most outcomes need
			-- agreement and a short deferral does not, and without somewhere
			-- to keep that, "proposed" would have to mean "in force" for
			-- everything — which makes the review queue decorative.
			"needs_approval"             ` + t.boolean + ` NOT NULL,
			"state"                      ` + t.kind + ` NOT NULL,
			-- Set when an approver sends a claim back for more, and cleared
			-- when the author revises it. Not a state of its own: the claim is
			-- still proposed and still applies to nothing, and what changed is
			-- whose turn it is. A fifth state would have to be reasoned about
			-- everywhere the other four are.
			"sent_back_at"               ` + t.timestamp + ` NULL,
			"proposed_by"                ` + t.ref + ` NOT NULL,
			"proposed_at"                ` + t.timestamp + ` NOT NULL,
			-- When this stopped applying: withdrawn by somebody, or lapsed
			-- because the code moved. Null while it is live. What a finding
			-- reports as its earlier decisions needs the date, and nothing
			-- else recorded one — an approval's withdrawn_at only exists
			-- where somebody had agreed.
			"ended_at"                   ` + t.timestamp + ` NULL,
			-- How the set this claim was part of was narrowed, where it was
			-- one of many recorded in a single action. Kept because "how were
			-- these chosen" is the question asked of a bulk judgment months
			-- later, and the words that narrowed the list are not in the
			-- reasoning: narrowing is how a candidate was found, and the
			-- reasoning is why the claim is true. Null for a claim made on
			-- its own.
			"selected_by"                ` + t.free + ` NULL,
			-- What this decision is a claim about, while it is still a live
			-- claim: the place and both upstream versions, hashed. Set to null
			-- the moment it is withdrawn or lapses, because a decision that no
			-- longer applies is history and must not block a fresh one.
			--
			-- The unique index over it is how "one live decision per code
			-- combination" is enforced by the database rather than by a check
			-- somebody remembers to write. Null values do not collide in a
			-- unique index on any of the four engines, which is what makes a
			-- rule that only applies to *some* rows portable at all — and a
			-- read-then-write check is exactly the shape two proposals
			-- arriving at once both walk through.
			"live_key"                   ` + t.hash + ` NULL,
			CONSTRAINT "decision_live_unique" UNIQUE ("live_key"),
			CONSTRAINT "decision_claim_fk" FOREIGN KEY ("claim_id") REFERENCES "claim"("id"),
			CONSTRAINT "decision_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "decision_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "decision_proposer_fk" FOREIGN KEY ("proposed_by") REFERENCES "person"("id")
		)` + t.suffix,

		// Found two ways, and both are hot.
		//
		// One index, not two, and it answers both questions asked of it. The
		// exact one is a finding asking whether a decision applies to it,
		// which is every version column matching as well as the structural
		// ones. The other drops the versions and asks "was there ever a
		// decision about this place" — which surfaces the reasoning behind one
		// that has lapsed, so somebody re-making it is not starting from a
		// blank page. That is a lookup on the first three columns, and a
		// B-tree that leads with them answers it with the same seek.
		//
		// A separate index on those three was here and is gone. The argument
		// that kept the narrow index on `finding` — that scanning it reads
		// fewer pages — turns on there being hundreds of thousands of rows to
		// read, and there are thousands of decisions rather than a finding per
		// place.
		`CREATE INDEX "decision_applies_idx" ON "decision" ("product_id", "vulnerability_id", "place_identity", "component_upstream_version", "consumer_upstream_version")`,
		`CREATE INDEX "decision_claim_idx" ON "decision" ("claim_id")`,

		// The reasoning, revised and never overwritten.
		//
		// A second person approves specific words. If those words can change
		// afterwards, the second pair of eyes reviewed something that is no
		// longer what stands — which is the whole control gone, silently. So
		// every revision is kept and readable, and an approval names one.
		//
		// Hung off the claim, because one act is one argument. Per decision, a
		// judgment reaching forty-four places held forty-four revisable copies
		// of one sentence: revising one returned that row to the queue and
		// left the other forty-three saying the old thing under a claim that
		// read as agreed.
		`CREATE TABLE "claim_revision" (
			"id"          ` + t.id + `,
			"claim_id"    ` + t.ref + ` NOT NULL,
			"ordinal"     ` + t.ref + ` NOT NULL,
			-- The text as somebody wrote it. Stored as source and never as
			-- rendered output: what is safe to render is a decision made when
			-- it is rendered, and text stored years ago predates rules written
			-- since.
			"body"        ` + t.text + ` NOT NULL,
			"written_by"  ` + t.ref + ` NOT NULL,
			"written_at"  ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "claim_revision_claim_fk" FOREIGN KEY ("claim_id") REFERENCES "claim"("id"),
			CONSTRAINT "claim_revision_author_fk" FOREIGN KEY ("written_by") REFERENCES "person"("id"),
			CONSTRAINT "claim_revision_unique" UNIQUE ("claim_id", "ordinal")
		)` + t.suffix,

		// Who agreed, and to what exactly.
		//
		// Kept rather than reduced to a flag on the decision, because an
		// approval that was later withdrawn is part of the record: it says a
		// second person did once agree, and to which words.
		`CREATE TABLE "claim_approval" (
			"id"           ` + t.id + `,
			"claim_id"     ` + t.ref + ` NOT NULL,
			"revision_id"  ` + t.ref + ` NOT NULL,
			"approved_by"  ` + t.ref + ` NOT NULL,
			"approved_at"  ` + t.timestamp + ` NOT NULL,
			-- Set when the reasoning was revised under it, or when somebody
			-- took the decision back.
			"withdrawn_at" ` + t.timestamp + ` NULL,
			-- What a bulk approval was, so undoing one is undoing a batch
			-- rather than hunting for what it touched.
			"batch"        ` + t.hash + ` NULL,
			-- How many findings this claim covered **when somebody agreed to
			-- it**.
			--
			-- Recorded rather than worked out later, because a decision is a
			-- claim about a combination of code and reaches by matching — a
			-- branch cut next month that still ships the same versions is
			-- covered too, with nobody having acted. Asking what it covers now
			-- answers a different question from what somebody consented to,
			-- and only one of the two can be recovered afterwards. Keeping the
			-- number at the time is what makes "agreed covering six, now
			-- covers sixty-one" a question anybody can ask.
			--
			-- One number rather than the three the interface shows. The split
			-- between here, already-matching and deliberately-carried is how
			-- it is presented; what the record needs is how much was agreed to.
			"covered"      ` + t.ref + ` NULL,
			CONSTRAINT "claim_approval_claim_fk" FOREIGN KEY ("claim_id") REFERENCES "claim"("id"),
			CONSTRAINT "claim_approval_revision_fk" FOREIGN KEY ("revision_id") REFERENCES "claim_revision"("id"),
			CONSTRAINT "claim_approval_approver_fk" FOREIGN KEY ("approved_by") REFERENCES "person"("id")
		)` + t.suffix,

		`CREATE INDEX "claim_approval_claim_idx" ON "claim_approval" ("claim_id")`,
		`CREATE INDEX "claim_approval_batch_idx" ON "claim_approval" ("batch")`,

		// Discussion, which is not the reasoning.
		//
		// The obvious mistake is treating all text on a finding as one thing.
		// Annotating an approved decision months later — "re-checked, still
		// true" — is ordinary, and it must not disturb the approval, because
		// an approval that fell over every time somebody added a note would
		// teach people not to add notes.
		//
		// A comment is overwritten when its author edits it, and no history is
		// kept beyond a marker that it happened. That is a deliberate
		// exception to keeping everything: discussion is not the record a
		// decision rests on, and that record is the revisions and the
		// approvals, which are kept in full.
		`CREATE TABLE "claim_comment" (
			"id"          ` + t.id + `,
			"claim_id"    ` + t.ref + ` NOT NULL,
			"body"        ` + t.text + ` NOT NULL,
			"written_by"  ` + t.ref + ` NOT NULL,
			"written_at"  ` + t.timestamp + ` NOT NULL,
			"edited_at"   ` + t.timestamp + ` NULL,
			CONSTRAINT "claim_comment_claim_fk" FOREIGN KEY ("claim_id") REFERENCES "claim"("id"),
			CONSTRAINT "claim_comment_author_fk" FOREIGN KEY ("written_by") REFERENCES "person"("id")
		)` + t.suffix,

		`CREATE INDEX "claim_comment_claim_idx" ON "claim_comment" ("claim_id")`,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downTriage(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{
		`DROP TABLE "claim_comment"`,
		`DROP TABLE "claim_approval"`,
		`DROP TABLE "claim_revision"`,
		`DROP TABLE "decision"`,
		`DROP TABLE "claim"`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
