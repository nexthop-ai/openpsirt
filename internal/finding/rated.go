package finding

// The rating in force, which belongs to a product.

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
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

// RatedOn is where a query finds the product it is asking about.
//
// The two spellings are named rather than passed as text. A placeholder cannot
// bind a column name, so the product half of this join is spliced in — and a
// function taking a string would leave nothing between it and a column name
// arriving from a query parameter except that today's callers all pass a
// literal. Naming them is what makes that structural rather than a habit
// (REQ-66).
type RatedOn string

const (
	// RatedOnStream is the product the row's stream belongs to, for a query
	// that spans products and reads each row's own.
	RatedOnStream RatedOn = "st.product_id"
	// RatedOnDecision is the product a decision was recorded in.
	RatedOnDecision RatedOn = "de.product_id"
	// ratedOnBound is one product, bound. Used through RatedHere.
	ratedOnBound RatedOn = "?"
)

// RatedFor is the left join that brings a product's own rating into a query
// that already joins vulnerability AS v.
//
// Left, because most issues are rated by nobody and those are the rows every
// list is mostly made of.
//
// Every caller already joined the vulnerability, because that is where the
// rating used to be. So this swaps a column for a join rather than adding one
// where none existed.
func RatedFor(product RatedOn) string {
	return `LEFT JOIN "issue_rating" AS ir ON ir.vulnerability_id = v.id` +
		` AND ir.product_id = ` + string(product)
}

// RatedHere is RatedFor with the product bound.
//
// The same join rather than a second spelling of it: written out twice, a
// change to one is a change the other quietly does not make.
var RatedHere = RatedFor(ratedOnBound)

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
		Where("product_id IN (?)", bun.List(products)).
		Where("vulnerability_id IN (?)", bun.List(issues)).
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
// What "wherever this ranks" means once a rating belongs to a product: a
// signal that moved for the issue moves the order in each of them, and each
// reads its own rating to work out what the order now is.
func productsHolding(ctx context.Context, db bun.IDB, vulnerabilityID int64) ([]int64, error) {
	var products []int64
	err := db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN target AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("st.product_id").
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("f.closed_at IS NULL").
		GroupExpr("st.product_id").
		OrderExpr("st.product_id").
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
const inThisProduct = `target_id IN (SELECT tg.id FROM "target" AS tg
	JOIN "stream" AS st ON st.id = tg.stream_id
	WHERE st.product_id = ?)`
