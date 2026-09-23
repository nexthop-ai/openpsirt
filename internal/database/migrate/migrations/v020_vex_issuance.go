// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// A generated VEX document going out.
//
// Beside the imported statement of somebody else's document, and the opposite
// direction: this is a document written here, about one build, that somebody
// sent to a customer.
//
// The document is assembled from what stands about the build at the moment it
// is asked for, so it holds no history of its own. A reader keeps documents by
// the identifier they carry, which means the identifier has to stay still
// while the version moves — that is what makes two documents revisions of one
// thing rather than two documents that happen to describe one build. Without a
// record of the act there is nothing for the version to count.
//
// What was published on a date cannot be worked out again once a decision is
// revised, a claim is withdrawn or a scan closes a finding, so the act is
// recorded when it happens, with the bytes that went out. The digest is what
// makes "is what is published still what we would generate" a question with a
// yes or no.
func vexIssuanceStatements(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "vex_issuance" (
			"id"        ` + t.id + `,
			-- The build the document is about, which is what its identifier
			-- names: one release built one way. A document about a second
			-- build is a different document rather than a revision of this
			-- one.
			"target_id" ` + t.ref + ` NOT NULL,
			-- Which issuance this is, counting from one. The document
			-- generated now is one past it, the way the next advisory is one
			-- past what has gone out.
			"ordinal"   ` + t.ref + ` NOT NULL,
			-- What went out, hashed over what the document says. The parts
			-- that move for reasons other than the content are left out, so
			-- that a document regenerated unchanged hashes the same.
			"digest"    ` + t.hash + ` NOT NULL,
			-- The bytes that went out, carrying the ordinal above as their
			-- version. Generated in the write that takes the ordinal, so the
			-- number a document states and the number it is recorded under
			-- are one number.
			"document"  ` + t.free + ` NOT NULL,
			"issued_by" ` + t.ref + ` NOT NULL,
			"issued_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "vex_issuance_once" UNIQUE ("target_id", "ordinal"),
			CONSTRAINT "vex_issuance_target_fk"
				FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "vex_issuance_by_fk" FOREIGN KEY ("issued_by") REFERENCES "person"("id")
		)` + t.suffix,
	}
}
