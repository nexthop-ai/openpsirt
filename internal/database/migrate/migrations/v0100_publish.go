// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// productV0100 is v0.10.0's declaration of the product table.
//
// v0.9.0's, with whether the product's security documents are served to
// anybody. Derived from the baseline's declaration, which v0.7.0's record of
// its schema holds; no release between changed it.
func productV0100(t *columnTypes) []string {
	made, indexes, err := pick(catalogBaseline(t), "product")
	if err != nil {
		panic(err)
	}
	made = withColumn(made, `"pair_approvers" INTEGER NULL,`,
		`-- Whether this product's security documents are served to anybody
			-- who asks, without signing in, where the deployment publishes at
			-- all. A default rather than a fill: a product publishes nothing
			-- until an administrator turns it on, whenever it was declared.
			"publishes"      `+t.boolean+` DEFAULT FALSE NOT NULL,`)
	return append([]string{made}, indexes...)
}

// claimV0100 is v0.10.0's declaration of the claim table.
//
// The baseline's, with whom a published statement made from the claim holds
// for. Derived from the baseline's declaration; no release between changed it.
func claimV0100(t *columnTypes) []string {
	made, indexes, err := pick(triageBaseline(t), "claim")
	if err != nil {
		panic(err)
	}
	made = withColumn(made, `"upgrade_to"     `+t.free+` NULL,`,
		`-- Whom a published statement made from this claim holds for:
			-- anybody shipping the component, or this product's own build. Null
			-- where the claim states none, and the reason it gives decides.
			"scope"          `+t.kind+` NULL,`)
	return append([]string{made}, indexes...)
}

// publishedDocumentV0100 is v0.10.0's declaration of the security documents
// served to anybody: one row per document, holding the revision a reader is
// handed now.
func publishedDocumentV0100(t *columnTypes) []string {
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

// productPublishesV0100 adds whether a product's documents are served. No
// product v0.9.0 held publishes. Stepped over where a start that stopped after
// adding it finds it there, which MySQL and MariaDB leave behind.
func productPublishesV0100(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if present, err := u.hasColumn("product", "publishes"); err != nil || present {
		return err
	}
	return u.change(productV0100(u.t), change{table: "product",
		add: []added{{column: "publishes"}}})
}

// claimScopeV0100 adds whom a claim's published statement holds for. No claim
// v0.9.0 held states one. Stepped over where it is already there.
func claimScopeV0100(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if present, err := u.hasColumn("claim", "scope"); err != nil || present {
		return err
	}
	return u.change(claimV0100(u.t), change{table: "claim", add: []added{{column: "scope"}}})
}

// createPublishedDocumentV0100 makes the published document table, stepped
// over where it is already there.
func createPublishedDocumentV0100(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if present, err := u.hasColumn("published_document", "id"); err != nil || present {
		return err
	}
	return u.create(publishedDocumentV0100(u.t), "published_document")
}

// upgraderIn is the upgrader over one step's transaction.
func upgraderIn(ctx context.Context, tx bun.Tx) (*upgrader, error) {
	t, err := types(ctx)
	if err != nil {
		return nil, err
	}
	return &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}, nil
}
