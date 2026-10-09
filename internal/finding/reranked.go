// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// Putting every open finding of an issue back in the order after a signal the
// issue carries has moved.

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Reranked puts every open finding of these issues back where the signals now
// say it belongs.
//
// Three of the four signals the order is worked out from are properties of
// the issue — known exploitation, exploitation likelihood, and the score —
// and a report raises them for the issue wherever it appears. The fourth, the
// rating, belongs to a product, so the order is worked out once per product
// holding the issue rather than once for the deployment. The order is stored
// per finding, so every build nothing rescanned holds a number computed from
// the signals as they were. A known-exploited issue in a shipped tag would sit
// below the triage line, answer no exploited filter, carry no exploited
// deadline and sort at the bottom until somebody rescanned that tag, which for
// a tag is never.
//
// It is not a cache being refreshed. The stored order describes an issue
// rather than a moment, so it is rewritten when the signals move; what is
// stored because it cannot be worked out again is a different thing and is
// not this.
//
// Only the exploited flag moves a deadline, and only for the rows it was
// raised on, counted from when this was learned — the same rule and the same
// moment the scanned build's own rows are clocked by. A score or a likelihood
// moving deliberately changes no clock: neither is in the deadline, and a
// clock reset by a revised number would never arrive.
//
// The scanned build's own scanner findings are left out of the order's
// rewrite: applying the scan has just ranked every one of them from the same
// ratings, read in the same transaction. Zero names no build. The exploited
// clock still reaches them, because a listing day moving earlier re-clocks a
// row the scan found already exploited and left alone.
//
// Takes the handle because the caller writes inside its own transaction: the
// scan that raised the signal and the re-ranking it forces are one act.
func Reranked(ctx context.Context, tx bun.IDB, issues []int64, learnedAt time.Time,
	scanned int64) error {

	if len(issues) == 0 {
		return nil
	}
	issues = append([]int64(nil), issues...)
	sort.Slice(issues, func(i, j int) bool { return issues[i] < issues[j] })

	signals, err := issueSignals(ctx, tx, issues)
	if err != nil {
		return err
	}

	// Exploitation first, issue by issue: it sets the flag the order reads.
	// Few issues become exploited in one scan, where a feed moves the
	// likelihood of nearly all of them.
	recorded := map[int64]bool{}
	var windows *Windows
	for _, id := range issues {
		issue := signals[id]
		if !issue.Exploited {
			continue
		}
		if windows == nil {
			loaded, err := LoadWindows(ctx, tx)
			if err != nil {
				return err
			}
			windows = &loaded
		}
		recorded[id], err = exploitationClocked(ctx, tx, id,
			*exploitationKnown(issue.ExploitedOn, learnedAt), learnedAt, *windows)
		if err != nil {
			return err
		}
	}

	// The order itself, product by product, from each one's own rating and
	// the flags each row now carries. The signal that moved is the issue's
	// and reaches every product holding it; what it is combined with is that
	// product's rating, so the same report leaves two products ordering the
	// issue differently — which is the point of a rating belonging to one.
	holding, err := productsHoldingAll(ctx, tx, issues, scanned)
	if err != nil {
		return err
	}
	var products []int64
	seen := map[int64]bool{}
	for _, each := range holding {
		for _, productID := range each {
			if !seen[productID] {
				seen[productID] = true
				products = append(products, productID)
			}
		}
	}
	sort.Slice(products, func(i, j int) bool { return products[i] < products[j] })
	rated := map[RatedKey]string{}
	err = database.IDsInBatches(ctx, issues, func(ctx context.Context, batch []int64) error {
		some, err := RatingsIn(ctx, tx, products, batch)
		for k, severity := range some {
			rated[k] = severity
		}
		return err
	})
	if err != nil {
		return err
	}

	// One statement per product and value of the order, over every issue it
	// is the value for.
	type order struct {
		productID int64
		rest      Rank
	}
	byOrder := map[order][]int64{}
	var orders []order
	for _, id := range issues {
		issue := signals[id]
		for _, productID := range holding[id] {
			inForce := Rating{
				Published:  issue.Published,
				Assessed:   rated[RatedKey{ProductID: productID, VulnerabilityID: id}],
				ScoreCenti: issue.ScoreCenti, LikelihoodPPM: issue.Likelihood,
			}
			key := order{productID, inForce.rest()}
			if _, held := byOrder[key]; !held {
				orders = append(orders, key)
			}
			byOrder[key] = append(byOrder[key], id)
		}
	}
	for _, key := range orders {
		err := database.IDsInBatches(ctx, byOrder[key], func(ctx context.Context, batch []int64) error {
			q := reranking(tx, key.productID, key.rest).
				Where("vulnerability_id IN (?)", bun.List(batch))
			if scanned != 0 {
				q = q.Where("NOT (target_id = ? AND kind = ?)", scanned, Vulnerable)
			}
			_, err := q.Exec(ctx)
			return err
		})
		if err != nil {
			return fmt.Errorf("move these issues in the order: %w", err)
		}
	}

	// A recorded flaw that learned it has just been given a scanned finding's
	// deadline above. Its own windows and its own start put it back. Asked
	// only then, because this runs for every issue whose likelihood a feed
	// moved.
	for _, id := range issues {
		if !recorded[id] {
			continue
		}
		for _, productID := range holding[id] {
			if _, err := recountOwn(ctx, tx, productID, []int64{id}, learnedAt); err != nil {
				return err
			}
		}
	}
	return nil
}

// signal is what one issue carries that the order is worked out from.
type signal struct {
	ID          int64      `bun:"id"`
	Exploited   bool       `bun:"exploited"`
	ExploitedOn *time.Time `bun:"exploited_on"`
	Published   string     `bun:"published"`
	ScoreCenti  int        `bun:"score_centi"`
	Likelihood  int        `bun:"likelihood_ppm"`
}

// issueSignals reads the signals of these issues.
func issueSignals(ctx context.Context, tx bun.IDB, issues []int64) (map[int64]signal, error) {
	out := make(map[int64]signal, len(issues))
	err := database.IDsInBatches(ctx, issues, func(ctx context.Context, batch []int64) error {
		var rows []signal
		// The published word, aliased as what it is: a product's own rating
		// is read apart, and Rating is what decides between them.
		if err := tx.NewSelect().
			TableExpr(`"vulnerability" AS "v"`).
			ColumnExpr(`v.id AS "id"`).
			ColumnExpr(`COALESCE(v.exploited, ?) AS "exploited"`, false).
			ColumnExpr(`v.exploited_on AS "exploited_on"`).
			ColumnExpr(`COALESCE(v.severity, '') AS "published"`).
			ColumnExpr(`COALESCE(v.score_centi, 0) AS "score_centi"`).
			ColumnExpr(`COALESCE(v.likelihood_ppm, 0) AS "likelihood_ppm"`).
			Where("v.id IN (?)", bun.List(batch)).
			Scan(ctx, &rows); err != nil {
			return err
		}
		for _, row := range rows {
			out[row.ID] = row
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read what is known about these issues: %w", err)
	}
	return out, nil
}

// productsHoldingAll is every product with an open finding of each issue,
// leaving out the scanner findings of one build. Zero leaves out nothing.
func productsHoldingAll(ctx context.Context, tx bun.IDB, issues []int64,
	scanned int64) (map[int64][]int64, error) {

	out := map[int64][]int64{}
	err := database.IDsInBatches(ctx, issues, func(ctx context.Context, batch []int64) error {
		var rows []struct {
			VulnerabilityID int64 `bun:"vulnerability_id"`
			ProductID       int64 `bun:"product_id"`
		}
		q := tx.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
			ColumnExpr(`st.product_id AS "product_id"`).
			Where("f.vulnerability_id IN (?)", bun.List(batch)).
			Where("f.closed_at IS NULL").
			GroupExpr("f.vulnerability_id, st.product_id").
			OrderExpr("f.vulnerability_id, st.product_id")
		if scanned != 0 {
			q = q.Where("NOT (f.target_id = ? AND f.kind = ?)", scanned, Vulnerable)
		}
		if err := q.Scan(ctx, &rows); err != nil {
			return err
		}
		for _, row := range rows {
			out[row.VulnerabilityID] = append(out[row.VulnerabilityID], row.ProductID)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read which products hold these issues: %w", err)
	}
	return out, nil
}
