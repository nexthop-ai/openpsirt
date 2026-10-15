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
// A recorded flaw's issue row is minted for it, so what it holds that names no
// publisher is the record's: the word, the score, the vector and its version,
// and every rating beside it with no source. A feed's rating names its source
// and stays. The word is put in force in the recording product where nothing
// rates the issue there already. Each statement steps over what an earlier
// start moved.
func moveRecordedRatingsV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	return u.run([]string{
		`INSERT INTO "recorded_rating"
			("vulnerability_id", "product_id", "severity", "score_centi", "vector", "score_version")
		SELECT DISTINCT "v"."id", "st"."product_id", NULLIF("v"."severity", ''), "v"."score_centi",
			NULLIF("v"."vector", ''), NULLIF("v"."score_version", '')
		FROM "finding" AS "f"
		JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"
		JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"
		JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"
		WHERE "f"."kind" = 'entered'
			AND COALESCE("v"."score_source", '') = ''
			AND (COALESCE("v"."severity", '') <> '' OR "v"."score_centi" IS NOT NULL)
			AND NOT EXISTS (SELECT 1 FROM "recorded_rating" AS "rr"
				WHERE "rr"."vulnerability_id" = "v"."id" AND "rr"."product_id" = "st"."product_id")`,
		`INSERT INTO "issue_rating" ("vulnerability_id", "product_id", "severity")
		SELECT "rr"."vulnerability_id", "rr"."product_id", "rr"."severity"
		FROM "recorded_rating" AS "rr"
		WHERE "rr"."severity" IS NOT NULL
			AND NOT EXISTS (SELECT 1 FROM "issue_rating" AS "ir"
				WHERE "ir"."vulnerability_id" = "rr"."vulnerability_id"
				AND "ir"."product_id" = "rr"."product_id")`,
		`DELETE FROM "vulnerability_rating"
		WHERE COALESCE("score_source", '') = ''
			AND "vulnerability_id" IN (SELECT "rr"."vulnerability_id" FROM "recorded_rating" AS "rr")`,
		`UPDATE "vulnerability" SET "severity" = NULL, "score_centi" = NULL, "vector" = NULL,
			"score_version" = NULL, "score_kind" = NULL
		WHERE COALESCE("score_source", '') = ''
			AND "id" IN (SELECT "rr"."vulnerability_id" FROM "recorded_rating" AS "rr")`,
	})
}
