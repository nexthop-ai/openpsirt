// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upScanDocument, downScanDocument)
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
// The contents are deleted. The row describing the document stays, with
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
func upScanDocument(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
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

	return apply(ctx, tx, statements)
}

func downScanDocument(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "scan_document_chunk", "scan_document")
}
