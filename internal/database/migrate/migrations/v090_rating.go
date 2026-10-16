// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// recordedRatingV090 is v0.9.0's declaration of the rating a product records
// a flaw at.
//
// One row per issue and product, held apart from the issue row every product
// reads, and apart from the rating in force, which a rating claim replaces and
// a withdrawal returns to this.
func recordedRatingV090(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "recorded_rating" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			-- The word it was recorded at, where one was given.
			"severity"         ` + t.kind + ` NULL,
			-- The CVSS rating it was recorded with, where a vector was worked
			-- out: the score derived from it, and its scheme's version.
			"score_centi"      ` + t.refNull + ` NULL,
			"vector"           ` + t.free + ` NULL,
			"score_version"    ` + t.free + ` NULL,
			CONSTRAINT "recorded_rating_unique" UNIQUE ("vulnerability_id", "product_id"),
			CONSTRAINT "recorded_rating_vulnerability_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "recorded_rating_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id")
		)` + t.suffix,
	}
}

// createRecordedRatingV090 makes the recorded rating table, stepped over where
// a start that stopped after making it finds it there.
func createRecordedRatingV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	present, err := u.hasColumn("recorded_rating", "id")
	if err != nil || present {
		return err
	}
	return u.create(recordedRatingV090(t), "recorded_rating")
}

// moveRecordedRatingsV090 takes the rating a flaw was recorded at off the
// issue row, where v0.8.0 wrote it, into the recording product's own.
//
// The row's word is the record's wherever the issue holds a recorded flaw.
// A scanned issue that absorbed a record in a merge is the exception: it
// holds a finding no person entered and is the kept side of a merge, and its
// word and score are the scanner's except where they are the absorbed
// record's own, which v0.8.0's merge copied onto it. A record filed under a
// published name keeps its own word on the row, because no report fills a
// word the row already holds. The score, its vector and its scheme are the
// record's only where they name no publisher, and so is every rating beside
// them with no source; where a feed's score holds the row, the record's
// newest unsourced rating is its score. The word is put in force in the
// recording product where nothing rates the issue there already. Each
// statement steps over what an earlier start moved.
func moveRecordedRatingsV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	unsourced := `COALESCE("v"."score_source", '') = ''`
	// scannedKept is whether an issue holds a scanned finding and absorbed
	// another in a merge.
	scannedKept := func(column string) string {
		return `(EXISTS (SELECT 1 FROM "finding" AS "scanned"
				WHERE "scanned"."vulnerability_id" = ` + column + ` AND "scanned"."kind" <> 'entered')
			AND EXISTS (SELECT 1 FROM "vulnerability_merge" AS "vm"
				WHERE "vm"."kept_id" = ` + column + `))`
	}
	// The kept issue's word, and its unsourced score and vector, matching
	// those of the issue it absorbed.
	wordOf := func(k, a string) string {
		return `NULLIF("` + k + `"."severity", '') = NULLIF("` + a + `"."severity", '')`
	}
	scoreOf := func(k, a string) string {
		return `(COALESCE("` + k + `"."score_source", '') = '' AND COALESCE("` + a + `"."score_source", '') = ''
			AND "` + k + `"."score_centi" = "` + a + `"."score_centi"
			AND COALESCE("` + k + `"."vector", '') = COALESCE("` + a + `"."vector", ''))`
	}
	held := func(column, of string) string {
		quoted := `"` + column + `"`
		return quoted + ` IN (SELECT "rr".` + quoted + ` FROM "recorded_rating" AS "rr"
			WHERE "rr"."vulnerability_id" = ` + of + ` AND "rr".` + quoted + ` IS NOT NULL)`
	}
	return u.run([]string{
		`INSERT INTO "recorded_rating"
			("vulnerability_id", "product_id", "severity", "score_centi", "vector", "score_version")
		SELECT DISTINCT "v"."id", "st"."product_id", NULLIF("v"."severity", ''),
			CASE WHEN ` + unsourced + ` THEN "v"."score_centi" END,
			CASE WHEN ` + unsourced + ` THEN NULLIF("v"."vector", '') END,
			CASE WHEN ` + unsourced + ` THEN NULLIF("v"."score_version", '') END
		FROM "finding" AS "f"
		JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"
		JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"
		JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"
		WHERE "f"."kind" = 'entered'
			AND (COALESCE("v"."severity", '') <> ''
				OR (` + unsourced + ` AND "v"."score_centi" IS NOT NULL))
			AND NOT ` + scannedKept(`"v"."id"`) + `
			AND NOT EXISTS (SELECT 1 FROM "recorded_rating" AS "rr"
				WHERE "rr"."vulnerability_id" = "v"."id" AND "rr"."product_id" = "st"."product_id")`,
		// A scanned issue kept in a merge: what it holds that the absorbed
		// record held, from the first merge that matches.
		`INSERT INTO "recorded_rating"
			("vulnerability_id", "product_id", "severity", "score_centi", "vector", "score_version")
		SELECT DISTINCT "k"."id", "st"."product_id",
			CASE WHEN ` + wordOf("k", "a") + ` THEN "k"."severity" END,
			CASE WHEN ` + scoreOf("k", "a") + ` THEN "k"."score_centi" END,
			CASE WHEN ` + scoreOf("k", "a") + ` THEN NULLIF("k"."vector", '') END,
			CASE WHEN ` + scoreOf("k", "a") + ` THEN NULLIF("k"."score_version", '') END
		FROM "finding" AS "f"
		JOIN "vulnerability" AS "k" ON "k"."id" = "f"."vulnerability_id"
		JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"
		JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"
		JOIN "vulnerability_merge" AS "km" ON "km"."kept_id" = "k"."id"
		JOIN "vulnerability" AS "a" ON "a"."id" = "km"."absorbed_id"
		WHERE "f"."kind" = 'entered'
			AND ` + scannedKept(`"k"."id"`) + `
			AND (` + wordOf("k", "a") + ` OR ` + scoreOf("k", "a") + `)
			AND "km"."id" = (SELECT MIN("km2"."id") FROM "vulnerability_merge" AS "km2"
				JOIN "vulnerability" AS "a2" ON "a2"."id" = "km2"."absorbed_id"
				WHERE "km2"."kept_id" = "k"."id"
					AND (` + wordOf("k", "a2") + ` OR ` + scoreOf("k", "a2") + `))
			AND NOT EXISTS (SELECT 1 FROM "recorded_rating" AS "rr"
				WHERE "rr"."vulnerability_id" = "k"."id" AND "rr"."product_id" = "st"."product_id")`,
		`INSERT INTO "issue_rating" ("vulnerability_id", "product_id", "severity")
		SELECT "rr"."vulnerability_id", "rr"."product_id", "rr"."severity"
		FROM "recorded_rating" AS "rr"
		WHERE "rr"."severity" IS NOT NULL
			AND NOT EXISTS (SELECT 1 FROM "issue_rating" AS "ir"
				WHERE "ir"."vulnerability_id" = "rr"."vulnerability_id"
				AND "ir"."product_id" = "rr"."product_id")`,
		// Where a feed's score holds the row, the record's own vector is the
		// newest rating beside it that names no publisher.
		`UPDATE "recorded_rating" SET
			"score_centi" = (SELECT "vr"."score_centi" FROM "vulnerability_rating" AS "vr"
				WHERE "vr"."vulnerability_id" = "recorded_rating"."vulnerability_id"
					AND COALESCE("vr"."score_source", '') = ''
				ORDER BY "vr"."generation" DESC LIMIT 1),
			"vector" = (SELECT "vr"."vector" FROM "vulnerability_rating" AS "vr"
				WHERE "vr"."vulnerability_id" = "recorded_rating"."vulnerability_id"
					AND COALESCE("vr"."score_source", '') = ''
				ORDER BY "vr"."generation" DESC LIMIT 1),
			"score_version" = (SELECT "vr"."score_version" FROM "vulnerability_rating" AS "vr"
				WHERE "vr"."vulnerability_id" = "recorded_rating"."vulnerability_id"
					AND COALESCE("vr"."score_source", '') = ''
				ORDER BY "vr"."generation" DESC LIMIT 1)
		WHERE "score_centi" IS NULL
			AND NOT ` + scannedKept(`"recorded_rating"."vulnerability_id"`) + `
			AND EXISTS (SELECT 1 FROM "vulnerability_rating" AS "vr"
				WHERE "vr"."vulnerability_id" = "recorded_rating"."vulnerability_id"
					AND COALESCE("vr"."score_source", '') = '')`,
		`DELETE FROM "vulnerability_rating"
		WHERE COALESCE("score_source", '') = ''
			AND "vulnerability_id" IN (SELECT "rr"."vulnerability_id" FROM "recorded_rating" AS "rr")
			AND (NOT ` + scannedKept(`"vulnerability_rating"."vulnerability_id"`) + `
				OR ` + held("vector", `"vulnerability_rating"."vulnerability_id"`) + `)`,
		`UPDATE "vulnerability" SET "severity" = NULL
		WHERE "id" IN (SELECT "rr"."vulnerability_id" FROM "recorded_rating" AS "rr")
			AND (NOT ` + scannedKept(`"vulnerability"."id"`) + `
				OR ` + held("severity", `"vulnerability"."id"`) + `)`,
		`UPDATE "vulnerability" SET "score_centi" = NULL, "vector" = NULL,
			"score_version" = NULL, "score_kind" = NULL
		WHERE COALESCE("score_source", '') = ''
			AND "id" IN (SELECT "rr"."vulnerability_id" FROM "recorded_rating" AS "rr")
			AND (NOT ` + scannedKept(`"vulnerability"."id"`) + `
				OR ` + held("score_centi", `"vulnerability"."id"`) + `)`,
	})
}
