package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upScan, downScan)
}

// The record of what arrived: which variant it was filed against, when the
// producer says it was built, when we received it, what it hashed to, and
// which credential sent it.
//
// The file itself is not kept for a branch — it is superseded the next night —
// so this row plus the extracted data is the whole record of an ingest. The
// hash is what makes a re-upload idempotent, and the parser version is what
// bounds the damage if a parser bug is found later.
func upScan(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		`CREATE TABLE "scan" (
			"id"             ` + t.id + `,
			"target_id"      ` + t.ref + ` NOT NULL,
			"content_hash"   ` + t.hash + ` NOT NULL,
			-- The identity the document carries for itself. It is what joins a
			-- vulnerability report to the inventory it was produced from, once
			-- both have been copied away from the build tree and their
			-- filenames mean nothing.
			"serial"         ` + t.free + ` NULL,
			"built_at"       ` + t.timestamp + ` NOT NULL,
			"received_at"    ` + t.timestamp + ` NOT NULL,
			"parser_version" ` + t.name + ` NOT NULL,
			"credential"     ` + t.name + ` NULL,
			-- Why a scan that was taken could not be read.
			--
			-- The status alone says that something went wrong and nothing about what. A
			-- producer whose files cannot be read has to be able to see the reason where
			-- they see the scan, rather than in a log only an operator of this deployment
			-- can reach.
			"failure"        ` + t.text + ` NULL,
			"status"         ` + t.kind + ` NOT NULL,
			-- What the inventory was made of, recorded when it is read.
			--
			-- Not statistics. "Placed" against "components" is the difference
			-- between a document that describes a graph and one that is a
			-- list, and a reader has no other way to tell: an inventory whose
			-- components are all placed nowhere produces findings that are
			-- individually correct and cannot answer "why is this here" about
			-- any of them. One unplaced component is ordinary and a producer
			-- emitting none of the edges is not, and only the ratio says
			-- which happened.
			--
			-- Null on a scan recorded before this was kept, which reads as
			-- "not known" rather than as zero.
			"components"     INTEGER NULL,
			"placed"         INTEGER NULL,
			CONSTRAINT "scan_target_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "scan_content_unique" UNIQUE ("target_id", "content_hash")
		)` + t.suffix,

		// Answering "what is the newest accepted scan for this variant" is on
		// the path of every ingest, so it gets its own index rather than a
		// scan of everything ever received.
		`CREATE INDEX "scan_newest_idx" ON "scan" ("target_id", "status", "built_at")`,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downScan(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DROP TABLE "scan"`)
	return err
}
