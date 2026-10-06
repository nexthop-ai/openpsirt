// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// credentialV060 is v0.6.0's declaration of pipeline keys and
// personal tokens.
//
// v0.1.0's, with the name in force beside the name. A name is unique among the
// credentials in force rather than among every credential there has been, so
// a withdrawn key's name may be given to a new one. What a key sent is
// recorded against the key's row, so a new key holding an old key's name
// reads back nothing the old one sent.
func credentialV060(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "api_key" (
			"id"           ` + t.id + `,
			"name"         ` + t.name + ` NOT NULL,
			"secret_hash"  ` + t.hash + ` NOT NULL,
			"product_id"   ` + t.ref + ` NOT NULL,
			"stream_id"    ` + t.refNull + ` NULL,
			"variant_id"   ` + t.refNull + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			"last_used_at" ` + t.timestamp + ` NULL,
			"revoked_at"   ` + t.timestamp + ` NULL,
			-- The name while the key is in force, and null once it is
			-- withdrawn. An administrator withdraws a key by its name, so two
			-- in force may not share one.
			"live_name"    ` + t.name + ` NULL,
			CONSTRAINT "api_key_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "api_key_stream_fk" FOREIGN KEY ("stream_id") REFERENCES "stream"("id"),
			CONSTRAINT "api_key_variant_fk" FOREIGN KEY ("variant_id") REFERENCES "variant"("id"),
			CONSTRAINT "api_key_secret_unique" UNIQUE ("secret_hash"),
			CONSTRAINT "api_key_live_unique" UNIQUE ("live_name")
		)` + t.suffix,

		`CREATE INDEX "api_key_product_idx" ON "api_key" ("product_id")`,

		`CREATE TABLE "personal_token" (
			"id"           ` + t.id + `,
			"name"         ` + t.name + ` NOT NULL,
			"secret_hash"  ` + t.hash + ` NOT NULL,
			"person_id"    ` + t.ref + ` NOT NULL,
			-- product_id narrows a token below its owner rather than above:
			-- what it reaches is the intersection, so pinning it to something
			-- they cannot read reaches nothing rather than granting it.
			"product_id"   ` + t.refNull + ` NULL,
			-- holds narrows a token to some of what its owner may do. NULL is
			-- everything they hold; empty is refused at the mint.
			"holds"        ` + t.name + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			"expires_at"   ` + t.timestamp + ` NOT NULL,
			"last_used_at" ` + t.timestamp + ` NULL,
			"revoked_at"   ` + t.timestamp + ` NULL,
			-- The name while the token is in force, and null once it is
			-- withdrawn. Its owner withdraws it by that name, so two of
			-- theirs in force may not share one.
			"live_name"    ` + t.name + ` NULL,
			CONSTRAINT "personal_token_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "personal_token_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "personal_token_secret_unique" UNIQUE ("secret_hash"),
			CONSTRAINT "personal_token_live_unique" UNIQUE ("person_id", "live_name")
		)` + t.suffix,
	}
}

// liveNames gives each credential table its name in force, and takes away
// the rule that kept a withdrawn name from being given again.
func (u *upgrader) liveNames() error {
	for _, c := range []struct{ table, unique, live string }{
		{"api_key", "api_key_name_unique", "api_key_live_unique"},
		{"personal_token", "personal_token_name_unique", "personal_token_live_unique"},
	} {
		// Filled by a statement of its own rather than as the column's
		// default, which MySQL and MariaDB refuse to compute from another
		// column.
		inForce := func() error {
			return u.run([]string{`UPDATE "` + c.table + `" SET "live_name" = "name" WHERE "revoked_at" IS NULL`})
		}
		if err := u.change(credentialV060(u.t), change{table: c.table,
			add: []added{{column: "live_name"}}, then: inForce,
			constraints: []string{c.live}}); err != nil {
			return err
		}
		// A rebuilt SQLite table is made without it. Dropped after the new
		// rule exists, because MySQL and MariaDB refuse to drop the index a
		// foreign key is served by, and a token's owner is served by either.
		if u.engine != database.SQLite {
			if err := u.dropUnique(c.table, c.unique); err != nil {
				return err
			}
		}
	}
	return nil
}

// dropUnique drops a uniqueness rule. PostgreSQL holds one as a constraint,
// and MySQL and MariaDB as an index of that name.
func (u *upgrader) dropUnique(table, name string) error {
	if u.engine == database.Postgres {
		return u.run([]string{`ALTER TABLE "` + table + `" DROP CONSTRAINT "` + name + `"`})
	}
	return dropIndex(u.ctx, u.raw, table, name)
}
