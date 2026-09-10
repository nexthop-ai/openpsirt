package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upCatalog, downCatalog)
}

// What a scan can be filed against: a product, one of its streams, and a
// variant it is built as. All three are declared before anything may target
// them, so a mistyped name is rejected rather than quietly creating a stream
// that looks real.
//
// Branches and tags share a table. They differ only in that a branch moves and
// a tag never does, and everything else about them is the same — a product,
// variants, findings, an end-of-life date.
func upCatalog(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		// name is the normalized form — lower case, trimmed — and is what
		// everything matches on. display_name keeps the spelling somebody
		// typed, because "SONiC" is how people write it and reading it back
		// as "sonic" looks like the tool got it wrong.
		//
		// Normalizing the stored value rather than comparing case-insensitively
		// is what makes this behave the same on every engine without any of
		// them being asked to: a lower-case value compares the same under any
		// collation.
		`CREATE TABLE "product" (
			"id"           ` + t.id + `,
			"name"         ` + t.name + ` NOT NULL,
			"display_name" ` + t.text + ` NOT NULL,
			"eol_on"       ` + t.date + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "product_name_unique" UNIQUE ("name")
		)` + t.suffix,

		// kind is 'branch' or 'tag'. parent_id is the branch a tag was cut
		// from, when that is known.
		`CREATE TABLE "stream" (
			"id"         ` + t.id + `,
			"product_id" ` + t.ref + ` NOT NULL,
			"name"         ` + t.name + ` NOT NULL,
			"display_name" ` + t.text + ` NOT NULL,
			"kind"       ` + t.kind + ` NOT NULL,
			"parent_id"  ` + t.refNull + ` NULL,
			"eol_on"     ` + t.date + ` NULL,
			-- When a tag actually went out, which is not when it was declared
			-- here. A release declared months after it shipped, or minutes
			-- before, both order wrongly against the others by their
			-- declaration — and the release-over-release chart labels its
			-- points with dates. Null where nobody has said, and then the
			-- first scan of it stands in: something was built on that day.
			"released_on" ` + t.date + ` NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "stream_name_unique" UNIQUE ("product_id", "name"),
			CONSTRAINT "stream_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "stream_parent_fk" FOREIGN KEY ("parent_id") REFERENCES "stream"("id")
		)` + t.suffix,

		// A variant is a way the product is built — a chip, an
		// architecture, an operating system. That is a property of the
		// product, so it is declared once and named once. Spelling it
		// per release is how one release ends up with a variant named
		// differently from the last, and three spellings are three
		// sets of findings that nothing says belong together.
		//
		// customer_facing feeds ranking, and defaults true because an
		// unclassified artifact should rank as though it ships.
		`CREATE TABLE "variant" (
			"id"              ` + t.id + `,
			"product_id"      ` + t.ref + ` NOT NULL,
			"name"            ` + t.name + ` NOT NULL,
			"display_name"    ` + t.text + ` NOT NULL,
			"customer_facing" ` + t.boolean + ` NOT NULL,
			"created_at"      ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "variant_name_unique" UNIQUE ("product_id", "name"),
			CONSTRAINT "variant_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id")
		)` + t.suffix,

		// Which of the product's variants a release was actually built as.
		// This is what a scan is filed against and what everything downstream
		// points at, so one identifier flows from a scan through to a finding.
		//
		// A release gains one when a scan first arrives for it. Nothing new is
		// named at that point — the product, the release and the variant were
		// all declared — so this records a fact the build reported rather than
		// creating something a typo could invent. It is also what keeps a
		// variant introduced later out of earlier releases: they simply have
		// no row for it.
		`CREATE TABLE "target" (
			"id"         ` + t.id + `,
			"stream_id"  ` + t.ref + ` NOT NULL,
			"variant_id" ` + t.ref + ` NOT NULL,
			"created_at" ` + t.timestamp + ` NOT NULL,
			-- Which scan last wrote here. Two workers applying two scans of
			-- one target at the same time would each read the open rows, each
			-- compute the same difference, and each write it — leaving two
			-- open rows where the whole shape assumes one. Updating this row
			-- first takes a lock every engine honors, so the second waits.
			"last_scan_id" ` + t.refNull + ` NULL,
			-- The same lock, for the other writer. Recording what a scanner
			-- found is a second pass over the same target, run by the same
			-- queue, with the same two-workers-at-once problem.
			"last_run_id" ` + t.refNull + ` NULL,
			CONSTRAINT "target_unique" UNIQUE ("stream_id", "variant_id"),
			CONSTRAINT "target_stream_fk" FOREIGN KEY ("stream_id") REFERENCES "stream"("id"),
			CONSTRAINT "target_variant_fk" FOREIGN KEY ("variant_id") REFERENCES "variant"("id")
		)` + t.suffix,

		`CREATE INDEX "target_variant_idx" ON "target" ("variant_id")`,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downCatalog(ctx context.Context, tx *sql.Tx) error {
	for _, table := range []string{"target", "variant", "stream", "product"} {
		if _, err := tx.ExecContext(ctx, `DROP TABLE `+table); err != nil {
			return err
		}
	}
	return nil
}

// columnTypes holds the spellings that differ between engines. Everything the
// application queries is portable; only the declarations are not.
type columnTypes struct {
	id        string // primary key, generated
	ref       string // foreign key column
	refNull   string // nullable foreign key column
	name      string // short identifier, indexed and compared
	free      string // text a producer supplies, of no length we control
	text      string // free text
	date      string // a calendar date
	timestamp string // a moment
	boolean   string
	kind      string
	hash      string // a hex digest
	blob      string // opaque bytes, a bounded slice of a larger document
	suffix    string
}

func typesFor(e database.Engine) *columnTypes {
	switch e {
	case database.Postgres:
		return &columnTypes{
			id: "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY", ref: "BIGINT", refNull: "BIGINT",
			name: "VARCHAR(191)", free: "TEXT", text: "TEXT", date: "DATE", timestamp: "TIMESTAMPTZ",
			boolean: "BOOLEAN", kind: "VARCHAR(16)", hash: "VARCHAR(64)", blob: "BYTEA",
		}
	case database.MySQL, database.MariaDB:
		// 191 keeps a unique key inside the index limit on older servers using
		// a four-byte character set.
		return &columnTypes{
			id: "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY", ref: "BIGINT", refNull: "BIGINT",
			name: "VARCHAR(191)", free: "TEXT", text: "TEXT", date: "DATE", timestamp: "DATETIME(6)",
			boolean: "TINYINT(1)", kind: "VARCHAR(16)", hash: "VARCHAR(64)",
			// Sixteen megabytes, which is far more than a chunk ever holds.
			// The smaller type tops out at 64 KB, which is not.
			blob: "MEDIUMBLOB",
			// The collation is pinned because these two default to
			// case-insensitive where the other two engines are case-sensitive.
			// Unpinned, declaring "Widget" and then filing a scan against
			// "widget" resolves on one pair and creates a second product on
			// the other — the declaration rule that exists to catch a typo
			// would itself behave differently by engine. Binary comparison is
			// what the other two already do.
			suffix: " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin",
		}
	case database.SQLite:
		// DATETIME, not TEXT: the driver decides how to return a value from
		// the declared type, and TEXT will not scan into a time.Time.
		return &columnTypes{
			id: "INTEGER PRIMARY KEY AUTOINCREMENT", ref: "INTEGER", refNull: "INTEGER",
			name: "TEXT", free: "TEXT", text: "TEXT", date: "DATE", timestamp: "DATETIME",
			boolean: "BOOLEAN", kind: "TEXT", hash: "TEXT", blob: "BLOB",
		}
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
