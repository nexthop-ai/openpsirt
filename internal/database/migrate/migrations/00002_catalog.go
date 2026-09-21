package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upCatalog, downCatalog)
}

// A scan is filed against a product, one of its streams, and a
// variant it is built as. All three are declared before anything may target
// them, so a mistyped name is rejected rather than quietly creating a stream
// that looks real.
//
// Branches and tags share a table. They differ only in that a branch moves and
// a tag never does, and everything else about them is the same — a product,
// variants, findings, an end-of-life date.
func upCatalog(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
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
			-- What a product considers worth triaging.
			--
			-- Five thousand findings is a list nobody reads, and the ones that drown it
			-- are the ones nobody was ever going to act on. Below this line a finding is
			-- still recorded, still counted and still reportable — it leaves the working
			-- list, not the system, because an auditor asking what we knew is entitled to
			-- an answer whether or not it was worth an afternoon.
			--
			-- On the product rather than in application_setting because products differ in
			-- what they can afford to ignore: one line for a whole estate is either too
			-- strict somewhere or too loose somewhere else. Null means the deployment's
			-- own line applies, which is the ordinary case and is why this is not NOT NULL
			-- — a product with no opinion should not have to state the default, or it
			-- would stop following it when the default changes.
			"triage_floor" ` + t.kind + ` NULL,
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
		//
		// retired_at takes a variant out of use without taking anything it
		// holds with it. Its findings, its decisions and the documents that
		// went out for it all name it, so the row stays and the lists stop
		// offering it — the same shape a team and a routing rule use. The
		// name stays spoken for while it is retired, and declaring it again
		// is what brings it back.
		`CREATE TABLE "variant" (
			"id"              ` + t.id + `,
			"product_id"      ` + t.ref + ` NOT NULL,
			"name"            ` + t.name + ` NOT NULL,
			"display_name"    ` + t.text + ` NOT NULL,
			"customer_facing" ` + t.boolean + ` NOT NULL,
			"created_at"      ` + t.timestamp + ` NOT NULL,
			"retired_at"      ` + t.timestamp + ` NULL,
			CONSTRAINT "variant_name_unique" UNIQUE ("product_id", "name"),
			CONSTRAINT "variant_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id")
		)` + t.suffix,

		// The product variant a release was actually built as.
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

	return apply(ctx, tx, statements)
}

func downCatalog(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "target", "variant", "stream", "product")
}
