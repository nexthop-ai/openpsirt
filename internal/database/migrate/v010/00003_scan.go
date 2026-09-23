// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package v010

import (
	"context"
	"database/sql"
)

func init() {
	register(upScan, downScan)
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
	t, err := types(ctx)
	if err != nil {
		return err
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

		// An upload refused before it became a scan.
		//
		// A scan row records what was taken. Something turned away at the
		// door never becomes one, so the two commonest real ingest failures —
		// a document nothing can read, and a clock that never moves, so every
		// build after the first is refused as older than what is held — left
		// the deployment nothing to look at. The producer was told and
		// nobody here was.
		//
		// What that cost is a coverage report that can say a build has gone
		// quiet and cannot say whether anybody is trying. Those want
		// different people: one is a pipeline nobody wired up, the other is a
		// pipeline failing nightly and reporting success to its own log.
		//
		// Kept per target rather than per attempt-and-forever: a producer
		// retrying a broken document writes one of these a minute, and what
		// anybody reads is the most recent.
		`CREATE TABLE "scan_refusal" (
			"id"           ` + t.id + `,
			"target_id"    ` + t.ref + ` NOT NULL,
			"at"           ` + t.timestamp + ` NOT NULL,
			-- Why it was turned away, in the words the producer was given, so
			-- the two ends of the conversation say the same thing.
			"reason"       ` + t.text + ` NOT NULL,
			-- What sent it, where a credential did. Null for the paths that
			-- do not carry one, which reads as "not known" rather than as
			-- nobody.
			"credential"   ` + t.name + ` NULL,
			-- What the document said it was built from, where it got far
			-- enough to say. The out-of-order case is exactly the one where
			-- this is the useful field.
			"built_at"     ` + t.timestamp + ` NULL,
			"content_hash" ` + t.hash + ` NULL,
			CONSTRAINT "scan_refusal_target_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			-- One per target. A refusal replaces the one before it, because
			-- what a report asks is whether this build is being refused now.
			CONSTRAINT "scan_refusal_target_unique" UNIQUE ("target_id")
		)` + t.suffix,
	}

	return apply(ctx, tx, statements)
}

func downScan(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "scan_refusal", "scan")
}
