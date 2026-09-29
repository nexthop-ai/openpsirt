// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// savedFilterV050 is v0.5.0's declaration of a kept narrowing of the
// findings list.
//
// v0.1.0's, which v0.2.0 to v0.4.0 left as it was, without the product.
func savedFilterV050(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "saved_filter" (
			"id"         ` + t.id + `,
			"person_id"  ` + t.ref + ` NOT NULL,
			-- What they called it, matched without regard to capitals and
			-- stored normalized like every other name people type,
			-- with the spelling they used kept beside it.
			"name"         ` + t.name + ` NOT NULL,
			"display_name" ` + t.free + ` NULL,
			-- The query string of the list it opens, without a leading "?".
			-- It names what the list is narrowed by and never where: the
			-- branch, the variant and anything naming one build or one run
			-- are the scope on screen, which a filter is applied within.
			"query"      ` + t.text + ` NOT NULL,
			-- What a saved filter proposes about what it catches, where
			-- somebody made it a prepared claim. All four absent is an
			-- ordinary saved filter.
			"outcome"       ` + t.kind + ` NULL,
			"justification" ` + t.free + ` NULL,
			"reasoning"     ` + t.text + ` NULL,
			"defer_days"    INTEGER NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "saved_filter_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			-- One name per person, so saving over one replaces it rather than
			-- leaving two that differ in a way nothing shows.
			CONSTRAINT "saved_filter_name_unique" UNIQUE ("person_id", "name")
		)` + t.suffix,
	}
}

// savedFilterV040 is v0.4.0's declaration of the same table, which a roll
// back puts back. Copied from the migration that made it rather than read from
// it, as every declaration a migration applies is.
func savedFilterV040(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "saved_filter" (
			"id"         ` + t.id + `,
			"person_id"  ` + t.ref + ` NOT NULL,
			"name"         ` + t.name + ` NOT NULL,
			"display_name" ` + t.free + ` NULL,
			"product_id" ` + t.ref + ` NOT NULL,
			"query"      ` + t.text + ` NOT NULL,
			"outcome"       ` + t.kind + ` NULL,
			"justification" ` + t.free + ` NULL,
			"reasoning"     ` + t.text + ` NULL,
			"defer_days"    INTEGER NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "saved_filter_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "saved_filter_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "saved_filter_name_unique" UNIQUE ("person_id", "product_id", "name")
		)` + t.suffix,
	}
}

// savedFilterColumns is every column both releases hold, in the order they
// are copied.
var savedFilterColumns = []string{"person_id", "name", "display_name", "query",
	"outcome", "justification", "reasoning", "defer_days", "created_at"}

// scopeWordsV050 is every word of the findings list's address that says where
// the list is rather than what it is narrowed by: the branch, the variant, a
// subtree of one build, what differs between the builds of a selection, what
// is spread over the variants of one branch, and the run that opened it.
//
// Copied rather than read from the list, so that what this release's upgrade
// strips does not move when the list gains a word.
var scopeWordsV050 = map[string]bool{
	"stream": true, "variant": true,
	"beneath": true, "beneath_version": true, "beneath_ecosystem": true, "beneath_namespace": true,
	"differs": true, "variants": true, "opened_by_run": true,
}

// unscopedV050 is one kept query without its scope. Every other parameter is
// kept exactly as written, since the list recognizes a kept filter as open by
// comparing its query with the address byte for byte.
func unscopedV050(query string) string {
	if query == "" {
		return query
	}
	var out []string
	for _, pair := range strings.Split(query, "&") {
		rawKey, _, _ := strings.Cut(pair, "=")
		if key, err := url.QueryUnescape(rawKey); err == nil && scopeWordsV050[key] {
			continue
		}
		out = append(out, pair)
	}
	return strings.Join(out, "&")
}

// keptFilter is one saved filter as the upgrade reads it.
type keptFilter struct {
	ID          int64          `bun:"id"`
	Person      int64          `bun:"person_id"`
	Name        string         `bun:"name"`
	DisplayName sql.NullString `bun:"display_name"`
	Query       string         `bun:"query"`
	CreatedAt   time.Time      `bun:"created_at"`
	// Product is how the product it was kept in is shown: its display name,
	// else its name.
	Product string `bun:"product"`
}

// savedFiltersPersonal takes the product out of every saved filter, which is
// one list per person from v0.5.0 on.
//
//   - Where one person kept one name in more than one product, the oldest
//     keeps the name and each other is renamed "Name (Product)". A rename that
//     another of theirs already holds takes a number after it, as
//     "Name (Product) 2".
//   - Every kept query loses its scope: the branch, the variant and anything
//     naming one build or one run.
//   - The product goes, and the name becomes unique to the person.
func savedFiltersPersonal(ctx context.Context, tx bun.Tx) error {
	var kept []keptFilter
	if err := tx.NewRaw(`SELECT "s"."id", "s"."person_id", "s"."name", "s"."display_name",
		"s"."query", "s"."created_at",
		COALESCE(NULLIF("p"."display_name", ''), "p"."name") AS "product"
		FROM "saved_filter" AS "s" JOIN "product" AS "p" ON "p"."id" = "s"."product_id"`).
		Scan(ctx, &kept); err != nil {
		return fmt.Errorf("read the kept filters: %w", err)
	}
	renamed := renamedV050(kept)
	for _, each := range kept {
		query := unscopedV050(each.Query)
		to, moving := renamed[each.ID]
		if !moving && query == each.Query {
			continue
		}
		name, display := each.Name, each.DisplayName
		if moving {
			name, display = foldedV050(to), sql.NullString{String: to, Valid: true}
		}
		if _, err := tx.NewRaw(`UPDATE "saved_filter" SET "name" = ?, "display_name" = ?, "query" = ?
			WHERE "id" = ?`, name, display, query, each.ID).Exec(ctx); err != nil {
			return fmt.Errorf("carry kept filter %d across: %w", each.ID, err)
		}
	}

	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	made, _, err := pick(savedFilterV050(t), "saved_filter")
	if err != nil {
		return err
	}
	if u.engine == database.SQLite {
		return u.rebuild(made, nil, change{table: "saved_filter"})
	}
	items, err := declared(made)
	if err != nil {
		return err
	}
	unique, err := items.constraint("saved_filter_name_unique")
	if err != nil {
		return err
	}
	person, err := items.constraint("saved_filter_person_fk")
	if err != nil {
		return err
	}
	if u.engine == database.Postgres {
		return u.run([]string{
			`ALTER TABLE "saved_filter" DROP CONSTRAINT "saved_filter_product_fk"`,
			`ALTER TABLE "saved_filter" DROP CONSTRAINT "saved_filter_name_unique"`,
			`ALTER TABLE "saved_filter" DROP COLUMN "product_id"`,
			`ALTER TABLE "saved_filter" ADD ` + unique,
		})
	}
	// MySQL and MariaDB serve the person's key with the unique index, and
	// refuse to drop an index a key is using. The key goes first and comes
	// back once the new index is there to serve it.
	for _, key := range []string{"saved_filter_person_fk", "saved_filter_product_fk"} {
		if err := u.dropKey("saved_filter", key); err != nil {
			return err
		}
	}
	return u.run([]string{
		`ALTER TABLE "saved_filter" DROP INDEX "saved_filter_name_unique"`,
		`ALTER TABLE "saved_filter" DROP COLUMN "product_id"`,
		`ALTER TABLE "saved_filter" ADD ` + unique,
		`ALTER TABLE "saved_filter" ADD ` + person,
	})
}

// renamedV050 is the name each filter moves to, for every filter whose name
// one of the same person's filters in another product holds too. The oldest
// holder keeps the name. Every name any of their filters holds is reserved
// before any is renamed, so a rename never takes a name somebody kept, and no
// step writes a name another row still holds.
func renamedV050(kept []keptFilter) map[int64]string {
	ordered := make([]keptFilter, len(kept))
	copy(ordered, kept)
	sort.SliceStable(ordered, func(i, j int) bool {
		if !ordered[i].CreatedAt.Equal(ordered[j].CreatedAt) {
			return ordered[i].CreatedAt.Before(ordered[j].CreatedAt)
		}
		return ordered[i].ID < ordered[j].ID
	})
	held := func(person int64, name string) string {
		return strconv.FormatInt(person, 10) + "\x00" + name
	}
	taken := map[string]bool{}
	for _, each := range ordered {
		taken[held(each.Person, each.Name)] = true
	}
	first := map[string]bool{}
	out := map[int64]string{}
	for _, each := range ordered {
		if !first[held(each.Person, each.Name)] {
			first[held(each.Person, each.Name)] = true
			continue
		}
		called := each.Name
		if each.DisplayName.Valid && strings.TrimSpace(each.DisplayName.String) != "" {
			called = strings.TrimSpace(each.DisplayName.String)
		}
		suffix := " (" + each.Product + ")"
		for again := 1; ; again++ {
			if again > 1 {
				suffix = " (" + each.Product + ") " + strconv.Itoa(again)
			}
			to := bound.HeadRunes(called, database.NameWidth-len([]rune(suffix))) + suffix
			if !taken[held(each.Person, foldedV050(to))] {
				taken[held(each.Person, foldedV050(to))] = true
				out[each.ID] = to
				break
			}
		}
	}
	return out
}

// savedFiltersProductsBack puts the product back on every saved filter, which
// is where v0.4.0 reads one.
//
// Nothing records which product a filter was kept in, and v0.5.0 offered each
// in every product, so each is kept in every product. A deployment with no
// product keeps none. A name the upgrade renamed keeps the rename.
func savedFiltersProductsBack(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	made, _, err := pick(savedFilterV040(t), "saved_filter")
	if err != nil {
		return err
	}
	var columns []string
	for _, c := range savedFilterColumns {
		columns = append(columns, `"`+c+`"`)
	}
	listed := strings.Join(columns, ", ")
	from := `"s".` + strings.Join(columns, `, "s".`)

	if u.engine == database.SQLite {
		kept, err := u.sqliteIndexes("saved_filter", nil)
		if err != nil {
			return err
		}
		stmts := []string{
			createsTable.ReplaceAllString(made, `CREATE TABLE "saved_filter_downgrading"`),
			`INSERT INTO "saved_filter_downgrading" (` + listed + `, "product_id") SELECT ` + from +
				`, "p"."id" FROM "saved_filter" AS "s" CROSS JOIN "product" AS "p"`,
			`DROP TABLE "saved_filter"`,
			`ALTER TABLE "saved_filter_downgrading" RENAME TO "saved_filter"`,
		}
		return u.run(append(stmts, kept...))
	}

	items, err := declared(made)
	if err != nil {
		return err
	}
	var defs []string
	for _, name := range []string{"saved_filter_name_unique", "saved_filter_product_fk", "saved_filter_person_fk"} {
		def, err := items.constraint(name)
		if err != nil {
			return err
		}
		defs = append(defs, `ALTER TABLE "saved_filter" ADD `+def)
	}
	product, err := items.column("product_id")
	if err != nil {
		return err
	}
	var stmts []string
	switch u.engine {
	case database.Postgres:
		stmts = append(stmts, `ALTER TABLE "saved_filter" DROP CONSTRAINT "saved_filter_name_unique"`)
		// The person's key is untouched there, so it is not declared again.
		defs = defs[:2]
	default:
		if err := u.dropKey("saved_filter", "saved_filter_person_fk"); err != nil {
			return err
		}
		stmts = append(stmts, `ALTER TABLE "saved_filter" DROP INDEX "saved_filter_name_unique"`)
	}
	stmts = append(stmts,
		`ALTER TABLE "saved_filter" ADD COLUMN `+strings.TrimSuffix(product, " NOT NULL")+` NULL`,
		// A copy in every product but the first, then the first on the row
		// itself. The second statement reads the rows still holding no
		// product, which the first did not write.
		`INSERT INTO "saved_filter" (`+listed+`, "product_id") SELECT `+from+`, "p"."id"
			FROM "saved_filter" AS "s" CROSS JOIN "product" AS "p"
			WHERE "s"."product_id" IS NULL AND "p"."id" <> (SELECT MIN("id") FROM "product")`,
		`UPDATE "saved_filter" SET "product_id" = (SELECT MIN("id") FROM "product")
			WHERE "product_id" IS NULL`,
		`DELETE FROM "saved_filter" WHERE "product_id" IS NULL`,
	)
	if u.engine == database.Postgres {
		stmts = append(stmts, `ALTER TABLE "saved_filter" ALTER COLUMN "product_id" SET NOT NULL`)
	} else {
		stmts = append(stmts, `ALTER TABLE "saved_filter" MODIFY COLUMN `+product)
	}
	return u.run(append(stmts, defs...))
}
