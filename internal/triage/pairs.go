package triage

import (
	"context"
	"fmt"
	"time"
)

// Pair is two people agreeing to each other's work in one product, whichever
// of them proposed.
type Pair struct {
	ProductID int64
	// First and Second are the two people, the lower identifier first, so a
	// pair reads the same whichever of them proposed.
	First, Second int64
	// Claims is how many claims ran between them, in either direction.
	Claims int
}

// Agreements is one product's standing agreements over a period, and the pairs
// they ran between.
type Agreements struct {
	ProductID int64
	// Claims is every claim in the product proposed in the period that
	// somebody other than its proposer agreed to and has not taken back.
	Claims int
	Pairs  []Pair
}

// AgreedSince is every product's agreements on claims proposed since a moment,
// by the pairs of people they ran between.
//
// A pair is two people rather than a proposer and an approver. The pattern is
// two people each agreeing to what the other proposes, so counting the
// directions apart halves the share of the pair it exists to find.
//
// Counted in claims rather than in rows. A claim over sixty places is one
// thing proposed and one thing agreed to, and a pair's share of the rows would
// be decided by whose claims happened to be broad.
//
// Unnarrowed, for the reason the count of what stands with nobody agreeing is:
// what it feeds is a condition told to administrators, which carries the fact
// and a link and never the claims.
func (s *Store) AgreedSince(ctx context.Context, since time.Time) ([]Agreements, error) {
	var rows []struct {
		ProductID  int64 `bun:"product_id"`
		ProposedBy int64 `bun:"proposed_by"`
		ApprovedBy int64 `bun:"approved_by"`
		Claims     int   `bun:"claims"`
	}
	// Grouped by the two people as they stand, and folded into pairs below.
	// Ordering the two within the statement needs the lesser and greater of
	// two values, which the four engines spell differently.
	err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim_approval" AS "ap" ON ap.claim_id = de.claim_id`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`de.proposed_by AS "proposed_by"`).
		ColumnExpr(`ap.approved_by AS "approved_by"`).
		ColumnExpr(`COUNT(DISTINCT de.claim_id) AS "claims"`).
		Where("ap.withdrawn_at IS NULL").
		Where("ap.approved_by <> de.proposed_by").
		Where("de.proposed_at >= ?", since).
		GroupExpr("de.product_id, de.proposed_by, ap.approved_by").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read who agrees with whom: %w", err)
	}
	var totals []struct {
		ProductID int64 `bun:"product_id"`
		Claims    int   `bun:"claims"`
	}
	err = s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim_approval" AS "ap" ON ap.claim_id = de.claim_id`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`COUNT(DISTINCT de.claim_id) AS "claims"`).
		Where("ap.withdrawn_at IS NULL").
		Where("ap.approved_by <> de.proposed_by").
		Where("de.proposed_at >= ?", since).
		GroupExpr("de.product_id").
		Scan(ctx, &totals)
	if err != nil {
		return nil, fmt.Errorf("count what was agreed to: %w", err)
	}

	type key struct{ product, first, second int64 }
	folded := map[key]int{}
	for _, row := range rows {
		first, second := row.ProposedBy, row.ApprovedBy
		if second < first {
			first, second = second, first
		}
		folded[key{row.ProductID, first, second}] += row.Claims
	}
	at := map[int64]int{}
	out := make([]Agreements, 0, len(totals))
	for _, total := range totals {
		at[total.ProductID] = len(out)
		out = append(out, Agreements{ProductID: total.ProductID, Claims: total.Claims})
	}
	for k, claims := range folded {
		i, ok := at[k.product]
		if !ok {
			continue
		}
		out[i].Pairs = append(out[i].Pairs, Pair{
			ProductID: k.product, First: k.first, Second: k.second, Claims: claims,
		})
	}
	return out, nil
}
