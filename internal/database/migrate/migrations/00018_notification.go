package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upNotification, downNotification)
}

// Everything somebody is told, and the two lifetimes that has.
//
// Everyone gets a notification area, not only administrators: a triager sees
// work arriving, a proposer sees a dismissal sent back, an approver sees what
// waits on them. The content differs by role and the mechanism does not.
//
// It works with no mail configured at all, which is the point. A self-hosted
// operator who never set up SMTP would otherwise have every operational alert
// sent into a void, and the people who most need telling that the tool itself
// is unwell are exactly the ones who have not opted into anything.
//
// The lifetimes are the design, not a column somebody added for tidiness
// . An event happened once and is acknowledged by the person it
// happened to: you were assigned this, your dismissal was sent back, somebody
// named you. A condition is true for as long as it is true and clears itself
// when it stops — a build that stopped being scanned should leave the list
// when it is scanned again, without anybody dismissing it. Treating the second
// as the first is how a count fills with problems that already went away, and
// then nobody reads it.
//
// So a condition carries a key naming what it is about, and the pass that
// derives conditions reconciles against it: what is true is opened, what is no
// longer true is cleared. Two rows for one condition about one thing is the
// failure that key exists to prevent, which is why it is unique per person.
func upNotification(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	statements := []string{
		`CREATE TABLE "notification" (
			"id"        ` + t.id + `,
			"person_id" ` + t.ref + ` NOT NULL,
			-- What happened, as a word the interface knows how to draw.
			"kind"      ` + t.name + ` NOT NULL,
			-- 'event' or 'condition'. An event is acknowledged; a condition
			-- clears itself when what it is about stops being true.
			"lifetime"  ` + t.kind + ` NOT NULL,
			-- What a condition is about, so the pass that derives them can
			-- tell "still true" from "true again". Empty for an event, which
			-- is about a moment rather than a state.
			"about"     ` + t.name + ` NOT NULL,
			-- The same value while the condition holds, and null once it has
			-- cleared. It exists to carry the uniqueness below: every engine
			-- here treats nulls as distinct in a unique index, so cleared rows
			-- never collide with each other while open ones still do — which
			-- is the invariant, expressed without a partial index that two of
			-- the four engines do not have.
			"about_open" ` + t.name + ` NULL,
			-- What to say, and where it points. The line is stored rather
			-- than derived at read time because it describes a moment: the
			-- finding it names may since have been decided, closed or
			-- reopened, and re-deriving it later would describe the world now
			-- rather than the world somebody was told about.
			"body"      ` + t.text + ` NOT NULL,
			"link"      ` + t.free + ` NOT NULL,
			-- Whether what this is about is a finding nobody has announced.
			--
			-- Recorded here rather than worked out when something is sent,
			-- because the answer belongs to the moment the row was written:
			-- a finding disclosed since would otherwise make an old message
			-- about an embargo readable, and one made private since would
			-- not make an old message about a public issue secret again. The
			-- channel that leaves the building reads this and says nothing
			-- but a link; the area inside it is unaffected, because
			-- reaching that is already the visibility check.
			"private"   ` + t.boolean + ` NOT NULL,
			-- Which product this is about, and which issue, where it is
			-- about either.
			--
			-- Columns rather than something derived from "about" or parsed
			-- back out of "concerns", because what a read narrows by cannot
			-- be a string another pass invented the shape of. Every read of
			-- this table is narrowed by them: what somebody was told about an
			-- undisclosed finding stops being readable when the role that
			-- reached it is withdrawn, and comes back if it is granted again,
			-- because they *were* told and destroying that record is what an
			-- auditor most wants to find (REQ-42 and REQ-43).
			--
			-- Nullable, because plenty is about neither: a mailbox that keeps
			-- refusing, an account somebody created, a build that stopped
			-- being scanned. A row marked private is refused without a
			-- product, so the narrowing has no hole to fall through.
			"product_id" ` + t.ref + ` NULL,
			"vulnerability_id" ` + t.ref + ` NULL,
			-- What an event was about, where it was about a finding.
			--
			-- Not "about" above, which carries a condition's identity and its
			-- uniqueness: an event that named one would be deduplicated
			-- against an unrelated row, which is why that column refuses one.
			-- This one is never matched on for uniqueness. It exists so the
			-- digest can answer "was this person already told about this",
			-- which is the whole of what a digest carries.
			"concerns"  ` + t.name + ` NULL,
			-- What makes one thing said to many people one thing to carry
			-- outside this deployment. Empty for everything personal.
			--
			-- A message about somebody's own work names them and is theirs;
			-- one saying a build's contents changed sharply is the same
			-- sentence for every reader of that product, and a channel wants
			-- it once however many people hold the product. The area inside
			-- the application is per person either way — this decides what a
			-- delivery is keyed on, which is the same question a condition's
			-- "about" answers for the rows a sweep opens.
			"together"  ` + t.name + ` NOT NULL,
			-- When this was carried outside the application, and how many
			-- times that has been tried.
			--
			-- A row nobody has sent is one to send, which makes retrying the
			-- ordinary path rather than a mechanism of its own: a message
			-- that failed is simply still unsent. The count is what stops
			-- that being forever — an address that refuses every time is a
			-- mailbox that has gone, and a sweep that keeps trying it is one
			-- that eventually does nothing else.
			"sent_at"   ` + t.timestamp + ` NULL,
			"attempts"  ` + t.ref + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			-- When they acknowledged it. Unread is the ordinary state, so it
			-- is the null one.
			"read_at"   ` + t.timestamp + ` NULL,
			-- When the condition stopped being true. Kept rather than deleted
			-- so that "this cleared" is answerable, and so a condition that
			-- comes back is a new row rather than an edit of an old one.
			"cleared_at" ` + t.timestamp + ` NULL,
			CONSTRAINT "notification_person_fk" FOREIGN KEY ("person_id")
				REFERENCES "person"("id"),
			CONSTRAINT "notification_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id"),
			CONSTRAINT "notification_vulnerability_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id")
		)` + t.suffix,

		// The area's own read: one person's unread, newest first. The
		// visibility narrowing that follows it is over one person's unread
		// rows, which is the small set this index already produces.
		`CREATE INDEX "notification_unread_idx"
			ON "notification" ("person_id", "read_at", "cleared_at")`,

		// One *open* row per condition per person. A build that has been quiet
		// for a week is one thing to be told, however many times the pass
		// runs, and a condition that comes back after clearing is a new row
		// rather than an edit of an old one.
		//
		// Keyed on about_open rather than on about and cleared_at: a unique
		// index over a nullable cleared_at would let two open rows through,
		// because null is distinct from null on all four engines — which is
		// the same property this relies on to let cleared rows accumulate.
		`CREATE UNIQUE INDEX "notification_condition_idx"
			ON "notification" ("person_id", "kind", "about_open")`,
	}
	return apply(ctx, tx, statements)
}

func downNotification(ctx context.Context, tx *sql.Tx) error {
	// The table goes and its indexes go with it. Dropping them first is what
	// broke two rollbacks already: MySQL and MariaDB refuse to drop an index a
	// foreign key is using to enforce itself.
	return dropTables(ctx, tx, "notification")
}
