// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// upstreamV0100 is v0.10.0's declaration of the upstream a product trusts: the
// provider whose published statements a fork takes, and how far it has been
// read.
func upstreamV0100(t *columnTypes) []string {
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
	}
}

// upstreamDocumentV0100 is v0.10.0's declaration of the documents an upstream
// lists: one row per document read, holding the revision last recorded.
func upstreamDocumentV0100(t *columnTypes) []string {
	return []string{
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

// vexStatementV0100 is v0.10.0's declaration of a third party's statements:
// v0.9.0's, with who here declined one and when.
func vexStatementV0100(t *columnTypes) []string {
	statements := vexStatementsV090(t)
	statements[0] = withColumn(statements[0], `"superseded_at" `+t.timestamp+` NULL,`,
		`-- When somebody here declined the statement, and who. A declined
			-- statement closes nothing and is offered to nobody. Null for one
			-- nobody declined.
			"declined_at" `+t.timestamp+` NULL,
			"declined_by" `+t.refNull+` NULL,`)
	return statements
}

// createUpstreamV0100 makes the two upstream tables, each stepped over where it
// is already there.
func createUpstreamV0100(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, table := range []struct {
		name     string
		declared func(*columnTypes) []string
	}{
		{"upstream", upstreamV0100},
		{"upstream_document", upstreamDocumentV0100},
	} {
		present, err := u.hasColumn(table.name, "id")
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.create(table.declared(u.t), table.name); err != nil {
			return err
		}
	}
	return nil
}

// statementDeclinedV0100 adds who declined a statement. No statement v0.9.0
// held was declined.
//
// Each column is added on its own and stepped over where it is already there:
// on MySQL and MariaDB each addition commits by itself, so a start that
// stopped between the two leaves the first and not the second.
func statementDeclinedV0100(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, column := range []string{"declined_at", "declined_by"} {
		present, err := u.hasColumn("vex_statement", column)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.change(vexStatementV0100(u.t), change{table: "vex_statement",
			add: []added{{column: column}}}); err != nil {
			return err
		}
	}
	return nil
}
