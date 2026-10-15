// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// The rating in force, which belongs to a product.

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/cvss"
)

// IssueRating is what one product rates an issue, as against what was
// published about it.
//
// A row exists only where somebody on that product has said something and it
// is in force, so its presence is the whole of "this product disagrees". A
// product nobody has rated the issue in inherits nothing: it reads the
// published rating until somebody on that team looks. A rating arriving from a
// product they cannot see is what this shape exists to remove.
//
// Separate from the claim it came from because a milder rating waits for a
// second person: a claim exists before it decides anything, and what ranks has
// to be readable without knowing which claims are live.
type IssueRating struct {
	bun.BaseModel `bun:"table:issue_rating,alias:ir"`

	ID              int64  `bun:"id,pk,autoincrement"`
	VulnerabilityID int64  `bun:"vulnerability_id,notnull"`
	ProductID       int64  `bun:"product_id,notnull"`
	Severity        string `bun:"severity,notnull"`
}

// RecordedRating is how bad the product that recorded a flaw here judged it
// when it was recorded: the word, and the CVSS rating where one was worked out.
//
// Held per product, never on the issue row. The issue row is read by every
// product holding the issue, and a recorded flaw's rating written there sorts,
// filters and clocks another product's findings by a judgment made where that
// product's readers may not look. The recording product's rating in force is
// this word until somebody there rates the issue otherwise, and returns to it
// when that rating is taken back.
type RecordedRating struct {
	bun.BaseModel `bun:"table:recorded_rating,alias:rr"`

	ID              int64   `bun:"id,pk,autoincrement"`
	VulnerabilityID int64   `bun:"vulnerability_id,notnull"`
	ProductID       int64   `bun:"product_id,notnull"`
	Severity        *string `bun:"severity"`
	ScoreCenti      *int    `bun:"score_centi"`
	Vector          *string `bun:"vector"`
	ScoreVersion    *string `bun:"score_version"`
}

// recordedIn reads the rating a product recorded a flaw at, nil where it
// recorded none.
func recordedIn(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (*RecordedRating, error) {
	var rows []RecordedRating
	if err := db.NewSelect().Model(&rows).
		Where(`"rr"."product_id" = ?`, productID).
		Where(`"rr"."vulnerability_id" = ?`, vulnerabilityID).
		Limit(1).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read how this was rated when it was recorded: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// recordRating writes the rating a product records a flaw at, and puts its
// word in force in that product. Nothing where neither a word nor a vector was
// given: an unrated flaw has no rating in force anywhere.
func recordRating(ctx context.Context, tx bun.IDB, productID, vulnerabilityID int64,
	severity string, scored *cvss.Scored) error {

	if severity == "" && scored == nil {
		return nil
	}
	row := &RecordedRating{VulnerabilityID: vulnerabilityID, ProductID: productID}
	if severity != "" {
		row.Severity = &severity
	}
	if scored != nil {
		vector, version := scored.Vector, scored.Scheme()
		row.ScoreCenti, row.Vector, row.ScoreVersion = &scored.ScoreCenti, &vector, &version
	}
	if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
		return fmt.Errorf("record how this product rates the flaw: %w", err)
	}
	if severity == "" {
		return nil
	}
	if _, err := tx.NewInsert().Model(&IssueRating{
		VulnerabilityID: vulnerabilityID, ProductID: productID, Severity: severity,
	}).Exec(ctx); err != nil {
		return fmt.Errorf("put the recorded rating in force: %w", err)
	}
	return nil
}

// RecordedVector is the CVSS vector a product recorded a flaw with, empty
// where it recorded none.
func RecordedVector(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (string, error) {
	row, err := recordedIn(ctx, db, productID, vulnerabilityID)
	if err != nil || row == nil || row.Vector == nil {
		return "", err
	}
	return *row.Vector, nil
}

// recordedColumn is one column of the rating a finding's own product recorded
// its issue at, for a query over findings as "f" joined to the issue as "v":
// the issue's own value, and the recorded one where the issue holds none and
// the finding is a recorded flaw.
//
// Asked only of a recorded flaw's rows, which are few, so the lookup is made
// for those rows alone rather than for every row a list reads.
//
// A text column the issue holds empty counts as holding nothing.
func recordedColumn(column string, text bool) string {
	own := `"v"."` + column + `"`
	if text {
		own = `NULLIF(` + own + `, '')`
	}
	return `CASE WHEN ` + own + ` IS NOT NULL THEN ` + own +
		` WHEN "f"."kind" = '` + string(Entered) + `' THEN (SELECT "rr"."` + column + `"` +
		` FROM "recorded_rating" AS "rr", "target" AS "rt", "stream" AS "rs"` +
		` WHERE "rt"."id" = "f"."target_id" AND "rs"."id" = "rt"."stream_id"` +
		` AND "rr"."product_id" = "rs"."product_id"` +
		` AND "rr"."vulnerability_id" = "f"."vulnerability_id") END`
}

// ScoreHere and ScoreVersionHere are a finding's score and the scheme it is
// on, the recording product's own for a recorded flaw.
var (
	ScoreHere        = recordedColumn("score_centi", false)
	ScoreVersionHere = recordedColumn("score_version", true)
)

// RatedKey is one issue in one product, which is what a rating is about.
type RatedKey struct {
	ProductID       int64
	VulnerabilityID int64
}

// RatingsIn reads what these products rate these issues.
//
// One statement for a page rather than one per row: a list of fifty spans at
// most fifty issues and a handful of products, and the pair is the unique key.
// Absent from the map means nobody rated it there, which is not the same as
// rating it as the world does — the caller falls back to the published word.
func RatingsIn(ctx context.Context, db bun.IDB, products, issues []int64) (map[RatedKey]string, error) {
	held := map[RatedKey]string{}
	if len(products) == 0 || len(issues) == 0 {
		return held, nil
	}
	var rows []IssueRating
	if err := db.NewSelect().Model(&rows).
		Column("vulnerability_id", "product_id", "severity").
		Where(`"product_id" IN (?)`, bun.List(products)).
		Where(`"vulnerability_id" IN (?)`, bun.List(issues)).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these products rate these issues: %w", err)
	}
	for _, row := range rows {
		held[RatedKey{row.ProductID, row.VulnerabilityID}] = row.Severity
	}
	return held, nil
}

// RatingIn reads what one product rates one issue, empty where it rates it
// nothing.
func RatingIn(ctx context.Context, db bun.IDB, productID, vulnerabilityID int64) (string, error) {
	held, err := RatingsIn(ctx, db, []int64{productID}, []int64{vulnerabilityID})
	if err != nil {
		return "", err
	}
	return held[RatedKey{productID, vulnerabilityID}], nil
}

// productsHolding is every product with an open finding of this issue.
//
// The meaning of "wherever this ranks" once a rating belongs to a product: a
// signal that moved for the issue moves the order in each of them, and each
// reads its own rating to work out what the order now is.
func productsHolding(ctx context.Context, db bun.IDB, vulnerabilityID int64) ([]int64, error) {
	var products []int64
	err := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		ColumnExpr(`"st"."product_id"`).
		Where(`"f"."vulnerability_id" = ?`, vulnerabilityID).
		Where(`"f"."closed_at" IS NULL`).
		GroupExpr(`"st"."product_id"`).
		OrderExpr(`"st"."product_id"`).
		Scan(ctx, &products)
	if err != nil {
		return nil, fmt.Errorf("read which products hold this issue: %w", err)
	}
	return products, nil
}

// inThisProduct narrows a statement over findings to one product, by the
// builds that product holds.
//
// Written as a condition on the target rather than as a join, because the
// statements that need it are updates and no engine here spells a joined
// update the same way.
const inThisProduct = `"target_id" IN (SELECT "tg"."id" FROM "target" AS "tg"
	JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"
	WHERE "st"."product_id" = ?)`

// inThisProductAs is the same condition over a qualified column, for the reads
// that alias the table they narrow.
//
// Named rather than written out, so every read that narrows a target to a
// product asks it in one spelling.
func inThisProductAs(column string) string {
	return column + ` IN (SELECT "tg"."id" FROM "target" AS "tg"
	JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"
	WHERE "st"."product_id" = ?)`
}
