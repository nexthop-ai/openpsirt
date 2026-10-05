// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"strconv"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// credentialV060 is the untagged release's declaration of pipeline keys and
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

// namesUnique makes every credential's name unique again, the way v0.5.0
// requires: to its owner for a token, and across the deployment for a key.
//
// The one in force keeps a name, and where none is the oldest does. Every
// other is renamed after its row, as "ci #7", which is the spelling v0.5.0's
// own upgrade gives a withdrawn name it could not keep.
func namesUnique(ctx context.Context, tx bun.Tx) error {
	for _, kind := range []credentialKind{keysV050, tokensV050} {
		var rows []credential
		if err := tx.NewRaw(`SELECT * FROM (`+kind.read+`) AS "credentials" ORDER BY "id"`).Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read every %s: %w", kind.what, err)
		}
		held := func(owner int64, name string) string {
			return strconv.FormatInt(owner, 10) + "\x00" + name
		}
		keeps := map[string]int64{}
		for _, one := range rows {
			at := held(one.Owner, one.Name)
			if _, taken := keeps[at]; !taken || !one.Revoked.Valid {
				keeps[at] = one.ID
			}
		}
		// Every name a credential keeps is reserved before anybody is
		// numbered, so a number never takes a name another holds.
		taken := map[string]bool{}
		for at := range keeps {
			taken[at] = true
		}
		for _, one := range rows {
			if keeps[held(one.Owner, one.Name)] == one.ID {
				continue
			}
			// One already named like a number keeps that name, so the number
			// taken here moves past it.
			id := strconv.FormatInt(one.ID, 10)
			number := " #" + id
			for again := 2; ; again++ {
				renamed := bound.HeadRunes(one.Name, database.NameWidth-len(number)) + number
				if taken[held(one.Owner, renamed)] {
					number = " #" + id + "." + strconv.Itoa(again)
					continue
				}
				taken[held(one.Owner, renamed)] = true
				if _, err := tx.NewRaw(`UPDATE "`+kind.table+`" SET "name" = ? WHERE "id" = ?`,
					renamed, one.ID).Exec(ctx); err != nil {
					return fmt.Errorf("rename a withdrawn %s: %w", kind.what, err)
				}
				break
			}
		}
	}
	return nil
}

// credentialV050 is v0.5.0's declaration of pipeline keys and personal
// tokens, which v0.1.0 made and no release since has changed: a name is unique
// among every credential there has been.
func credentialV050(t *columnTypes) []string {
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
			CONSTRAINT "api_key_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "api_key_stream_fk" FOREIGN KEY ("stream_id") REFERENCES "stream"("id"),
			CONSTRAINT "api_key_variant_fk" FOREIGN KEY ("variant_id") REFERENCES "variant"("id"),
			CONSTRAINT "api_key_secret_unique" UNIQUE ("secret_hash"),
			CONSTRAINT "api_key_name_unique" UNIQUE ("name")
		)` + t.suffix,

		`CREATE INDEX "api_key_product_idx" ON "api_key" ("product_id")`,

		`CREATE TABLE "personal_token" (
			"id"           ` + t.id + `,
			"name"         ` + t.name + ` NOT NULL,
			"secret_hash"  ` + t.hash + ` NOT NULL,
			"person_id"    ` + t.ref + ` NOT NULL,
			"product_id"   ` + t.refNull + ` NULL,
			"holds"        ` + t.name + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			"expires_at"   ` + t.timestamp + ` NOT NULL,
			"last_used_at" ` + t.timestamp + ` NULL,
			"revoked_at"   ` + t.timestamp + ` NULL,
			CONSTRAINT "personal_token_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "personal_token_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "personal_token_secret_unique" UNIQUE ("secret_hash"),
			CONSTRAINT "personal_token_name_unique" UNIQUE ("person_id", "name")
		)` + t.suffix,
	}
}

// everNames gives back the rule v0.5.0 holds, that a name is never given
// twice, once namesUnique has made it true.
func (u *upgrader) everNames() error {
	for _, c := range []struct{ table, unique, live, columns string }{
		{"api_key", "api_key_name_unique", "api_key_live_unique", `"name"`},
		{"personal_token", "personal_token_name_unique", "personal_token_live_unique", `"person_id", "name"`},
	} {
		if u.engine == database.SQLite {
			made, indexes, err := pick(credentialV050(u.t), c.table)
			if err != nil {
				return err
			}
			if err := u.rebuild(made, indexes, change{table: c.table}); err != nil {
				return err
			}
			continue
		}
		// The old rule before the new one goes, for the foreign key MySQL and
		// MariaDB serve from whichever of the two leads with the owner.
		if err := u.run([]string{`ALTER TABLE "` + c.table + `" ADD CONSTRAINT "` + c.unique +
			`" UNIQUE (` + c.columns + `)`}); err != nil {
			return err
		}
		if err := u.dropUnique(c.table, c.live); err != nil {
			return err
		}
		if err := u.run([]string{`ALTER TABLE "` + c.table + `" DROP COLUMN "live_name"`}); err != nil {
			return err
		}
	}
	return nil
}
