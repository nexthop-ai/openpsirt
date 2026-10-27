// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// repositoryV0110 is v0.11.0's declaration of what a product says about the
// repositories its builds are made from: where a location may link to, and
// whose source it keeps.
func repositoryV0110(t *columnTypes) []string {
	return []string{
		// A repository host a product's links may point at. A remote on no
		// host here is shown as text.
		`CREATE TABLE "repository_host" (
			"id"               ` + t.id + `,
			"product_id"       ` + t.ref + ` NOT NULL,
			-- The remotes it covers, normalized: a host, or a host and the
			-- path a mirror keeps its copies under.
			"remote"           ` + t.free + ` NOT NULL,
			-- The hash of the remote, because the remote is longer than an
			-- index key may be on some engines.
			"remote_identity"  ` + t.hash + ` NOT NULL,
			-- The web address the covered repositories are under, which is
			-- the host links open on.
			"web"              ` + t.free + ` NOT NULL,
			-- The kind of server, which names the templates, or custom.
			"style"            ` + t.kind + ` NOT NULL,
			-- The templates of a custom server: a file's lines, and two
			-- commits compared.
			"file_template"    ` + t.free + ` NULL,
			"compare_template" ` + t.free + ` NULL,
			CONSTRAINT "repository_host_remote_unique" UNIQUE ("product_id", "remote_identity"),
			CONSTRAINT "repository_host_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id")
		)` + t.suffix,

		// What a product says about the code under a path prefix of its
		// checkouts: the repository it is, where an upload names none, and
		// whether its source is kept. The empty prefix is the whole product.
		`CREATE TABLE "repository_path" (
			"id"               ` + t.id + `,
			"product_id"       ` + t.ref + ` NOT NULL,
			-- From the top of the checkout, with no leading or trailing slash.
			"prefix"           ` + t.free + ` NOT NULL,
			"prefix_identity"  ` + t.hash + ` NOT NULL,
			-- The repository and the branch links name where an upload states
			-- no repositories. Such links are approximate.
			"remote"           ` + t.free + ` NULL,
			"branch"           ` + t.free + ` NULL,
			-- Whether source snippets under the prefix are kept. Null takes
			-- the setting of the nearest prefix that states one.
			"snippets"         ` + t.boolean + ` NULL,
			-- Whether the snippets of a code finding included in its flaw's disclosure are disclosed
			-- with its flaw. Null takes the nearest prefix that states one,
			-- and none stating one strips them.
			"disclosed_snippets" ` + t.boolean + ` NULL,
			CONSTRAINT "repository_path_prefix_unique" UNIQUE ("product_id", "prefix_identity"),
			CONSTRAINT "repository_path_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id")
		)` + t.suffix,
	}
}

// createRepositoryV0110 makes the repository tables, stepped over where they
// are already there.
func createRepositoryV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, table := range []string{"repository_host", "repository_path"} {
		present, err := u.hasColumn(table, "id")
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.create(repositoryV0110(u.t), table); err != nil {
			return err
		}
	}
	return nil
}
