// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// documentUploadV0110 is v0.11.0's declaration of the record of each VEX
// document and supplier advisory that arrived for a product.
func documentUploadV0110(t *columnTypes) []string {
	return []string{
		// One row per arrival, taken or turned away, and never replaced. An
		// administrator uploads by hand, and a feed steps past a document
		// once it has read or refused it, so nothing here retries on a
		// timer the way a pipeline sending an inventory does.
		//
		// What the document says is in the statements. This is who sent it,
		// how, when, and what became of it.
		`CREATE TABLE "document_upload" (
			"id"                 ` + t.id + `,
			"product_id"         ` + t.ref + ` NOT NULL,
			-- Which kind of document it is, in the vocabulary a statement's
			-- source uses.
			"source"             ` + t.kind + ` NOT NULL,
			-- The publisher, normalized as a statement's is, and the name
			-- the publisher gave the document. Empty where the upload was
			-- turned away before either was read, and the name empty for a
			-- statement set, which carries none.
			"publisher"          ` + t.name + ` NOT NULL,
			"document_id"        ` + t.name + ` NOT NULL,
			-- The file name a client gave, or the address a feed fetched it
			-- from. Empty where the client gave none.
			"document"           ` + t.free + ` NOT NULL,
			-- Over the bytes that arrived. Null where they were never read
			-- whole.
			"digest"             ` + t.hash + ` NULL,
			-- Who uploaded it, spelled as a scan's sender is, or the feed
			-- that fetched it. One of the two, never both.
			"credential"         ` + t.name + ` NULL,
			"advisory_source_id" ` + t.refNull + ` NULL,
			"received_at"        ` + t.timestamp + ` NOT NULL,
			-- Completed or refused, and what the sender was told where it was
			-- refused.
			"status"             ` + t.kind + ` NOT NULL,
			"reason"             ` + t.text + ` NULL,
			-- How many statements it left standing and how many earlier ones
			-- it set aside, as it was taken. Zero for a refusal.
			"recorded"           INTEGER NOT NULL,
			"superseded"         INTEGER NOT NULL,
			CONSTRAINT "document_upload_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id"),
			CONSTRAINT "document_upload_feed_fk" FOREIGN KEY ("advisory_source_id")
				REFERENCES "advisory_source"("id")
		)` + t.suffix,
		// A product's uploads of one kind, newest first, which is the list.
		`CREATE INDEX "document_upload_list_idx" ON "document_upload"
			("product_id", "source", "received_at")`,
		// What a feed fetched, for the foreign key.
		`CREATE INDEX "document_upload_feed_idx" ON "document_upload" ("advisory_source_id")`,
	}
}

// createDocumentUploadV0110 makes the record of VEX document and supplier
// advisory uploads, stepped over where it is already there. v0.10.0 kept no
// such record, so it starts empty: what arrived before the upgrade is in the
// statements and the history of administrative changes.
func createDocumentUploadV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if present, err := u.hasColumn("document_upload", "id"); err != nil || present {
		return err
	}
	return u.create(documentUploadV0110(u.t), "document_upload")
}
