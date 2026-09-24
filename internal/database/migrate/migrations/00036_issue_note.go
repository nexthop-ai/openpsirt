// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upIssueNote, downIssueNote)
}

// A note for whoever decides, left without recording a judgment.
//
// **There was nowhere to put one.** A comment hangs off a claim, and the
// finding screen shows the box only where a claim already exists, so the first
// person to say anything about an issue had to record a judgment in order to
// say it. Assignment carries no message either: it takes a person or a team
// and nothing else.
//
// **Keyed on the issue and the product**, the way a rating is, and for the
// same reason. A row in the findings list is one issue at one fold, and one
// issue is often several rows: measured against the seeded image, 786 of 5,840
// open issues sit on more than one row, the worst at eleven, across
// golang.org/x/net and the standard library. A note attached to a row would
// have been written on one of eleven and hidden from the other ten.
//
// **Not merged into a claim's thread.** A claim is keyed on a place and a note
// on an issue, so they cannot become one record — two threads rendered near
// each other, and the claim's record stays exactly what people wrote about the
// claim. That matters where an approval points at one revision of a
// justification and editing the text withdraws it.
//
// **What it said before is kept**, the way a claim comment's is: a note is
// part of the record that goes public at disclosure, and a record whose
// earlier text is unrecoverable is readable rather than checkable.
func upIssueNote(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "issue_note" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			-- What was written, as source. Stored the way every other piece of
			-- text somebody typed is: rendering happens on the way out, and
			-- text stored years ago predates rules written since.
			"body"             ` + t.text + ` NOT NULL,
			"written_by"       ` + t.ref + ` NOT NULL,
			"written_at"       ` + t.timestamp + ` NOT NULL,
			-- That the author changed it. What it said before is in the table
			-- below.
			"edited_at"        ` + t.timestamp + ` NULL,
			CONSTRAINT "issue_note_issue_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "issue_note_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id"),
			CONSTRAINT "issue_note_author_fk" FOREIGN KEY ("written_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// A thread is read whole, oldest first, so the identifier is in the
		// key rather than sorted afterwards.
		`CREATE INDEX "issue_note_thread_idx" ON "issue_note" ("vulnerability_id", "product_id", "id")`,

		// What a note said before it was changed. The previous text, written
		// when it is replaced, rather than every version including the current
		// one: the note row holds what it says now, and this holds what it
		// stopped saying.
		`CREATE TABLE "issue_note_revision" (
			"id"          ` + t.id + `,
			"note_id"     ` + t.ref + ` NOT NULL,
			-- Which version this was, counting from one. The current text is
			-- one past the highest here.
			"ordinal"     ` + t.ref + ` NOT NULL,
			"body"        ` + t.text + ` NOT NULL,
			-- When it stopped saying that. Who wrote it is on the note: only
			-- its author may change one, so a revision has no separate author.
			"replaced_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "issue_note_revision_fk" FOREIGN KEY ("note_id")
				REFERENCES "issue_note"("id"),
			CONSTRAINT "issue_note_revision_once" UNIQUE ("note_id", "ordinal")
		)` + t.suffix,
	}

	return apply(ctx, tx, statements)
}

func downIssueNote(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "issue_note_revision", "issue_note")
}
