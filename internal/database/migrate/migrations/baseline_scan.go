// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// The record of what arrived: which variant it was filed against, when the
// producer says it was built, when we received it, what it hashed to, and
// which credential sent it.
//
// The file itself is not kept for a branch — it is superseded the next night —
// so this row plus the extracted data is the whole record of an ingest. The
// hash is what makes a re-upload idempotent, and the parser version is what
// bounds the damage if a parser bug is found later.
func scanBaseline(t *columnTypes) []string {
	return []string{
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
			-- What the document called the thing it is about, in its own
			-- spelling, and empty where it named no component of its own.
			--
			-- Kept here rather than on the component, because the component is
			-- stored by name alone on purpose: a package identifier carries the
			-- version, the version moves every build, and the root's identity
			-- moving takes every edge hanging off it with it. This is a fact
			-- about one document rather than an identity, so it belongs beside
			-- the serial and what the inventory was made of.
			"root_identifier" ` + t.text + ` NULL,
			CONSTRAINT "scan_target_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "scan_content_unique" UNIQUE ("target_id", "content_hash")
		)` + t.suffix,

		// Answering "what is the newest accepted scan for this variant" is on
		// the path of every ingest, so it gets its own index rather than a
		// scan of everything ever received.
		`CREATE INDEX "scan_newest_idx" ON "scan" ("target_id", "status", "built_at")`,

		// A build's newest arrival, one seek to the end of the range. The
		// front page, the scans screen, the check for a build gone quiet and
		// the product list each ask it for every declared build at once.
		`CREATE INDEX "scan_recency_idx" ON "scan" ("target_id", "received_at")`,

		// An upload refused before it became a scan.
		//
		// A scan row records what was taken. Something turned away at the
		// door never becomes one, so the two commonest real ingest failures —
		// a document nothing can read, and a clock that never moves, so every
		// build after the first is refused as older than what is held — left
		// the deployment nothing to look at. The producer was told and
		// nobody here was.
		//
		// The gain is a coverage report that can say a build has gone
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
}

// The documents a build sent, held from arrival until they have been read.
//
// They live in the database rather than on a disk or in a bucket. Each of the
// alternatives fails one of the constraints already settled: more than one
// replica runs, so a local file is not there for whoever picks the work up;
// and an object store is optional by decision, so ingest cannot be the thing
// that makes it mandatory. The database is the one place every deployment
// already has.
//
// Retention is not symmetric. A nightly scan is superseded the next night and
// its contents are deleted once it has been read; a tagged release keeps them,
// because re-scanning it years later needs both what it contained and what the
// build had already argued about its own patches.
//
// What is deleted is the contents. The row describing the document stays, with
// the hash of the bytes that arrived and when they were let go — so a build
// asked to send a file again can be told whether what it sent is what we read,
// and so a scan whose contents are gone still says what it was made of rather
// than looking like a scan that arrived with nothing.
//
// Content is split across rows. A single value of tens of megabytes runs into
// a server's maximum packet size on two of the four engines, and the limit is
// configuration rather than something a client can discover. Rows of a bounded
// size stay well inside every default, and let a document be read as a stream
// rather than held whole.
func scanDocumentBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "scan_document" (
			"id"           ` + t.id + `,
			"scan_id"      ` + t.ref + ` NOT NULL,
			"kind"         ` + t.kind + ` NOT NULL,
			"ordinal"      INTEGER NOT NULL,
			"content_hash" ` + t.hash + ` NOT NULL,
			"size_bytes"   BIGINT NOT NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			"discarded_at" ` + t.timestamp + `,
			CONSTRAINT "scan_document_place_unique" UNIQUE ("scan_id", "kind", "ordinal"),
			CONSTRAINT "scan_document_scan_id_fk" FOREIGN KEY ("scan_id") REFERENCES "scan"("id")
		)` + t.suffix,

		`CREATE TABLE "scan_document_chunk" (
			"id"          ` + t.id + `,
			"document_id" ` + t.ref + ` NOT NULL,
			"seq"         INTEGER NOT NULL,
			"body"        ` + t.blob + ` NOT NULL,
			CONSTRAINT "scan_document_chunk_seq_unique" UNIQUE ("document_id", "seq"),
			CONSTRAINT "scan_document_chunk_document_id_fk" FOREIGN KEY ("document_id") REFERENCES "scan_document"("id")
		)` + t.suffix,
	}
}
