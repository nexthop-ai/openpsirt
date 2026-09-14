package triage

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// What would make an approver disagree.
//
// **An approver is shown the claim and the reasoning and nothing that argues
// against them**, which is the rubber stamp the queue's whole shape was
// written against — so this is a weakness in a control rather than a card
// layout. The material already exists: the finding's own detail carries the
// decisions made elsewhere and what else sits at the place. What was missing
// is putting it where the judgment is made rather than a page away from it.
//
// **Two counts and no argument.** It does not say a claim is wrong — nothing
// here can know that — it says what a careful reader would go and look up, so
// that not looking is a choice rather than an omission.

// Counter is what argues against a claim, in numbers.
type Counter struct {
	// Elsewhere is what has already been agreed about this same issue at other
	// places, by outcome. A dismissal here where six places called it affected
	// is the case worth a second look.
	Elsewhere map[string]int
	// Undecided is how many other issues sit undecided at the same place. A
	// claim in a run of forty is a different thing from a claim on its own:
	// it is usually right and it is also how a run gets waved through.
	Undecided int
}

// Said reports whether there is anything to say at all.
func (c Counter) Said() bool { return len(c.Elsewhere) > 0 || c.Undecided > 0 }

// counters reads both, for a whole page of claims at once.
//
// One statement each rather than one per card: a page of fifty claims read a
// row at a time is a hundred round trips before the queue draws, which is the
// shape that makes a card carry less than it should.
func (s *Store) counters(ctx context.Context, subject access.Subject,
	representatives []Decision) (map[int64]Counter, error) {

	out := map[int64]Counter{}
	if len(representatives) == 0 {
		return out, nil
	}
	issues := make([]int64, 0, len(representatives))
	places := make([]string, 0, len(representatives))
	products := make([]int64, 0, len(representatives))
	for _, row := range representatives {
		issues = append(issues, row.VulnerabilityID)
		places = append(places, row.PlaceIdentity)
		products = append(products, row.ProductID)
	}

	// What has been agreed about the same issue somewhere else. Approved
	// only: a proposal is one person's opinion, and counting proposals here
	// would let two people in a queue agree with each other by being counted
	// at each other.
	//
	// The claim's own place is not excluded, and that is deliberate. A
	// place identity is a pair of names with no product in it, so
	// excluding by place alone would drop a decision in *another* product
	// that happens to ship the same pair — which is exactly the
	// counter-evidence worth having. Nothing of the claim's own can be
	// counted here anyway: it is in the queue, so it is proposed, and one
	// live decision per place means the place it sits at holds no approved
	// one.
	var agreed []struct {
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Outcome         string `bun:"outcome"`
		Places          int    `bun:"places"`
	}
	elsewhere := s.db.NewSelect().Model((*Decision)(nil)).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		ColumnExpr(`de.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`cl.outcome AS "outcome"`).
		ColumnExpr(`COUNT(DISTINCT de.place_identity) AS "places"`).
		Where("de.vulnerability_id IN (?)", bun.List(issues)).
		Where("de.state = ?", Approved).
		Where("de.live_key IS NOT NULL").
		GroupExpr("de.vulnerability_id, cl.outcome")
	if err := readableBy(elsewhere, subject, "de").Scan(ctx, &agreed); err != nil {
		return nil, fmt.Errorf("read what was decided about this elsewhere: %w", err)
	}
	byIssue := map[int64]map[string]int{}
	for _, row := range agreed {
		if byIssue[row.VulnerabilityID] == nil {
			byIssue[row.VulnerabilityID] = map[string]int{}
		}
		byIssue[row.VulnerabilityID][row.Outcome] += row.Places
	}

	// How much else at the same place nobody has answered, by the same test
	// every screen uses for "undecided": no live claim covering it at the
	// versions the code holds now.
	var open []struct {
		ProductID int64  `bun:"product_id"`
		Place     string `bun:"place_identity"`
		Issues    int    `bun:"issues"`
	}
	undecided := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`st.product_id AS "product_id"`).
		ColumnExpr(`f.place_identity AS "place_identity"`).
		ColumnExpr(`COUNT(DISTINCT f.vulnerability_id) AS "issues"`).
		Where("f.closed_at IS NULL").
		Where("f.place_identity IN (?)", bun.List(places)).
		Where("st.product_id IN (?)", bun.List(products)).
		Where(`NOT EXISTS (SELECT 1 FROM "decision" AS "de"
			WHERE de.product_id = st.product_id
			  AND de.vulnerability_id = f.vulnerability_id
			  AND de.place_identity = f.place_identity
			  AND de.live_key IS NOT NULL
			  AND ` + finding.KeyMatches + `)`).
		GroupExpr("st.product_id, f.place_identity")
	if err := readableFindings(undecided, subject, "f", "st.product_id").
		Scan(ctx, &open); err != nil {
		return nil, fmt.Errorf("read what else is undecided there: %w", err)
	}
	byPlace := map[string]int{}
	for _, row := range open {
		byPlace[fmt.Sprintf("%d %s", row.ProductID, row.Place)] = row.Issues
	}

	for _, row := range representatives {
		out[row.ID] = Counter{
			Elsewhere: byIssue[row.VulnerabilityID],
			Undecided: byPlace[fmt.Sprintf("%d %s", row.ProductID, row.PlaceIdentity)],
		}
	}
	return out, nil
}
