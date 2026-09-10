package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upAttachment, downAttachment)
}

// A file hanging off an issue, and the record of it that outlives the bytes.
//
// **The bytes are not here**. What this table holds is the reference
// the text uses, what the file is, where it went, who put it there, and — when
// somebody has to take a file back out — what was removed and why.
//
// **It hangs off the issue in the product**, which is the unit a decision, an
// embargo and a comment already use. Not a finding row: text is written against
// a decision and a decision covers every place an issue sits at, so binding a
// file to whichever of forty-eight rows somebody was looking at would lose it
// the day that row closed while its siblings stayed open.
//
// **There is no visibility column, deliberately.** Whether a file may be read
// is whether its issue may be read, asked at the moment of the request. A copy
// taken at upload would still say "private" after the embargo it documents had
// ended, which is the shape of every stale-value defect: correct when written,
// wrong from then on, and nothing reports it.
func upAttachment(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		`CREATE TABLE "attachment" (
			"id"               ` + t.id + `,
			-- What the text refers to, and the only identifier that
			-- ever leaves this deployment. Unguessable rather than sequential:
			-- authorization is what protects a file, but a reference somebody
			-- can enumerate turns "which issues have attachments" into a
			-- question an outsider can ask by counting.
			"token"            ` + t.name + ` NOT NULL,
			-- What it is about. Both, because an issue is only an issue
			-- somewhere: the same CVE in two products is two pieces of work
			-- and two sets of readers.
			"product_id"       ` + t.ref + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- What it was called when it arrived, for the disposition header.
			-- Kept as given and never used as a path.
			"filename"         ` + t.text + ` NOT NULL,
			-- The type **we** decided, never the one that was uploaded.
			-- Stored because it is what gets served, and because
			-- deciding it again later would apply today's allowlist to a file
			-- accepted under an older one.
			"content_type"     ` + t.name + ` NOT NULL,
			"size_bytes"       BIGINT NOT NULL,
			-- The digest of what was stored. Not the key: two identical files
			-- are two attachments, because redacting one must not blank the
			-- other. It is here so that a redaction can say what it
			-- removed after the bytes are gone.
			"digest"           ` + t.hash + ` NOT NULL,
			-- Where it went in the store. Ours to choose and never derived
			-- from the filename, so nothing a person typed reaches a path.
			"object_key"       ` + t.name + ` NOT NULL,
			"uploaded_by"      ` + t.ref + ` NOT NULL,
			"uploaded_at"      ` + t.timestamp + ` NOT NULL,
			-- When saved text first referred to it. Null is an upload nothing
			-- points at — somebody dragged a file in and closed the tab — and
			-- that is what the sweep collects. Set once and never
			-- cleared: text is append-only, so a reference that existed goes
			-- on existing in the revision that made it.
			"attached_at"      ` + t.timestamp + ` NULL,
			-- The tombstone. The row stays and the reference in the
			-- text stays; what goes is the file, and these three say that it
			-- was deliberate, who did it and why. A reason is required of them
			-- for the same reason moving a disclosure date is.
			"redacted_at"      ` + t.timestamp + ` NULL,
			"redacted_by"      ` + t.refNull + ` NULL,
			"redacted_reason"  ` + t.text + ` NULL,
			CONSTRAINT "attachment_token_unique" UNIQUE ("token"),
			CONSTRAINT "attachment_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "attachment_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "attachment_uploaded_by_fk" FOREIGN KEY ("uploaded_by") REFERENCES "person"("id"),
			CONSTRAINT "attachment_redacted_by_fk" FOREIGN KEY ("redacted_by") REFERENCES "person"("id")
		)` + t.suffix,

		// What hangs off one issue, which is what a finding screen lists.
		`CREATE INDEX "attachment_issue_idx"
			ON "attachment" ("product_id", "vulnerability_id")`,

		// What nothing points at yet, for the sweep. Leading with the column
		// the sweep tests for null, so it walks only the candidates rather
		// than every attachment ever made.
		`CREATE INDEX "attachment_unattached_idx"
			ON "attachment" ("attached_at", "uploaded_at")`,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downAttachment(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{`DROP TABLE "attachment"`} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}
