package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upCommentHistory, downCommentHistory)
}

// What a comment said before it was changed.
//
// **An edit overwrote and recorded only that it happened.** A reasoning's
// revisions are kept because an approval points at one revision of the words
// agreed to — and a comment is part of the same record that
// goes public at disclosure, so "what it said before" being
// unrecoverable makes that record readable and not checkable, which is the
// property the whole append-only history exists for.
//
// **The previous text, written when it is replaced**, rather than every
// version including the current one. The comment row holds what it says now;
// this holds what it stopped saying, which is the part that was being lost.
func upCommentHistory(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		`CREATE TABLE "claim_comment_revision" (
			"id"         ` + t.id + `,
			"comment_id" ` + t.ref + ` NOT NULL,
			-- Which version this was, counting from one. The current text is
			-- one past the highest here.
			"ordinal"    ` + t.ref + ` NOT NULL,
			-- What it said, as source. Stored the way every other piece of
			-- text somebody typed is: rendering happens on the way out, and
			-- text stored years ago predates rules written since.
			"body"       ` + t.text + ` NOT NULL,
			-- When it stopped saying that. Who wrote it is on the comment: only
			-- its author may change one, so a revision has no separate author.
			"replaced_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "claim_comment_revision_fk" FOREIGN KEY ("comment_id") REFERENCES "claim_comment"("id"),
			CONSTRAINT "claim_comment_revision_once" UNIQUE ("comment_id", "ordinal")
		)` + t.suffix,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downCommentHistory(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{`DROP TABLE "claim_comment_revision"`} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
