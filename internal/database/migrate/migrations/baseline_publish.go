// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// publishedDocumentBaseline declares the security documents served to anybody:
// one row per document, holding the revision a reader is handed now.
func publishedDocumentBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "published_document" (
			"id"           ` + t.id + `,
			"product_id"   ` + t.ref + ` NOT NULL,
			-- Which document this is: a CSAF VEX document about one issue, or
			-- an OpenVEX document about one branch or tag.
			"kind"         ` + t.kind + ` NOT NULL,
			-- What the document is about within the product: the issue's
			-- name, or the branch or tag's.
			"subject"      ` + t.name + ` NOT NULL,
			-- Where it is served, below the address documents are published
			-- at, and a digest of that path, which is what a request is
			-- matched on. The path itself outgrows a key every engine can
			-- index.
			"path"         ` + t.text + ` NOT NULL,
			"path_digest"  ` + t.hash + ` NOT NULL,
			-- What a feed lists it under.
			"tracking_id"  ` + t.text + ` NOT NULL,
			"title"        ` + t.text + ` NOT NULL,
			-- The revision held, counting from one, and when the first and
			-- this one were released.
			"version"      INTEGER NOT NULL,
			"first_at"     ` + t.timestamp + ` NOT NULL,
			"current_at"   ` + t.timestamp + ` NOT NULL,
			-- The statuses the deployment published when this revision was
			-- written. A revision written under a wider setting than the one
			-- in force is not served.
			"statuses"     ` + t.name + ` NOT NULL,
			-- A digest of what the document states, with its dates, version
			-- and history left out. A new revision is written only where it
			-- moves.
			"settled"      ` + t.hash + ` NOT NULL,
			-- When the product stopped having anything to say about this
			-- subject. Not served while set.
			"withdrawn_at" ` + t.timestamp + ` NULL,
			-- The bytes a reader is handed.
			"document"     ` + t.free + ` NOT NULL,
			CONSTRAINT "published_document_once" UNIQUE ("product_id", "kind", "subject"),
			CONSTRAINT "published_document_path" UNIQUE ("path_digest"),
			CONSTRAINT "published_document_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id")
		)` + t.suffix,
	}
}

// upstreamBaseline declares the upstream a product trusts, the provider whose
// published statements a fork takes and how far it has been read, and the
// documents it lists: one row per document read, holding the revision last
// recorded.
func upstreamBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "upstream" (
			"id"           ` + t.id + `,
			-- One upstream per product. A fork descends from one project.
			"product_id"   ` + t.ref + ` NOT NULL,
			-- Where the upstream describes what it publishes: its provider
			-- description. Every request the pass makes goes to this host.
			"url"          ` + t.free + ` NOT NULL,
			-- Whose statements they are, as the provider description named
			-- its publisher when an administrator trusted it.
			"publisher"    ` + t.name + ` NOT NULL,
			-- The key its documents are signed with, as an administrator
			-- confirmed it: the fingerprint and the armored public key. Both
			-- null where the upstream signs nothing.
			"fingerprint"  ` + t.name + ` NULL,
			"public_key"   ` + t.free + ` NULL,
			-- A key the upstream names that is not the one trusted, where it
			-- names one. Nothing is read while it is set, until an
			-- administrator trusts the upstream again.
			"key_offered"  ` + t.name + ` NULL,
			-- What each listing last answered with, so the next request asks
			-- whether it moved: its entity tag and its date, by address.
			"listings"     ` + t.free + ` NULL,
			-- When a pass last tried the upstream, when one last succeeded,
			-- and what stopped the last attempt.
			"fetched_at"   ` + t.timestamp + ` NULL,
			"reached_at"   ` + t.timestamp + ` NULL,
			"failed"       ` + t.free + ` NULL,
			"trusted_by"   ` + t.ref + ` NOT NULL,
			"trusted_at"   ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "upstream_once" UNIQUE ("product_id"),
			CONSTRAINT "upstream_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "upstream_by_fk" FOREIGN KEY ("trusted_by") REFERENCES "person"("id")
		)` + t.suffix,

		`CREATE TABLE "upstream_document" (
			"id"           ` + t.id + `,
			"upstream_id"  ` + t.ref + ` NOT NULL,
			-- Where it is served, and a digest of that address, which is what
			-- it is matched on. The address outgrows a key every engine can
			-- index.
			"url"          ` + t.free + ` NOT NULL,
			"url_digest"   ` + t.hash + ` NOT NULL,
			-- The name its statements are recorded under.
			"tracking_id"  ` + t.name + ` NOT NULL,
			-- When the listing said it last moved, as the listing wrote it.
			-- A listing writing another moment is a revision to read.
			"listed_at"    ` + t.name + ` NOT NULL,
			-- A digest of the bytes recorded.
			"digest"       ` + t.hash + ` NOT NULL,
			"recorded_at"  ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "upstream_document_once" UNIQUE ("upstream_id", "url_digest"),
			CONSTRAINT "upstream_document_upstream_fk" FOREIGN KEY ("upstream_id")
				REFERENCES "upstream"("id")
		)` + t.suffix,
	}
}
