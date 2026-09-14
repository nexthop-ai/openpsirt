package triage

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Carry takes chosen judgments onto a new line as claims waiting for
// agreement.
//
// **It carries reasoning forward and never conclusions.** Each one arrives as
// a claim needing approval, with the words from the old line to start from
// rather than to start without. A version moved, which is exactly what makes
// the old judgment stop applying — so somebody has to look at it again, and
// what is inherited is the thinking rather than the answer.
//
// **Only what was offered.** A caller naming a decision the preview classified
// as already applying, or as covering nothing here, is choosing something it
// was not asked about: the first has already happened and the second has
// nothing to happen to. Both are refused rather than quietly skipped, because
// a caller that got the set wrong should hear so.
//
// **Bounded, like every other action that writes many rows**.
func (s *Store) Carry(ctx context.Context, subject access.Subject, fromTarget, toTarget int64,
	chosen []int64, cap int) (int, error) {

	if len(chosen) == 0 {
		return 0, nil
	}
	if cap <= 0 {
		cap = DefaultTogetherCap
	}
	if len(chosen) > cap {
		return 0, fmt.Errorf("that would carry %d judgments and this deployment allows %d at "+
			"once", len(chosen), cap)
	}

	db, ok := s.db.(*bun.DB)
	if !ok {
		return 0, fmt.Errorf("this store is already inside a transaction")
	}
	carried := 0
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		carried = 0
		within := &Store{db: tx, now: s.now}

		// What the new line would inherit, read through the same rule
		// that shows it — so a caller cannot carry something the
		// preview would not offer, and the two cannot come to disagree
		// about which those are.
		//
		// Read inside the transaction, and this is the read that most
		// needed to be. It decides every row written below: what each
		// claim says, which place it is about, and whether it may be
		// carried at all. Read before the transaction began, a retry —
		// or a first attempt that merely waited — carried a judgment
		// somebody withdrew in the meantime, onto a line the old claim
		// no longer applies to, with the words from a claim that has
		// since been revised. The offer and the writing have to see
		// the same database or the rule "only what was offered" is
		// about a world that has moved.
		offered, err := within.WouldCarry(ctx, subject, fromTarget, toTarget)
		if err != nil {
			return err
		}
		available := make(map[int64]Inherited, len(offered.Moved)+len(offered.Postponed))
		for _, one := range append(append([]Inherited{}, offered.Moved...), offered.Postponed...) {
			available[one.DecisionID] = one
		}
		wanted := make([]Inherited, 0, len(chosen))
		for _, id := range chosen {
			one, ok := available[id]
			if !ok {
				return fmt.Errorf("decision %d is not one this line was offered", id)
			}
			wanted = append(wanted, one)
		}

		for _, one := range wanted {
			// The place is read from the new line's own findings rather than
			// copied from the old claim: the versions are what a decision is
			// keyed on and they are the thing that moved, so copying them
			// would write a claim keyed to a build it is not about.
			place, err := within.placeOnLine(ctx, toTarget, one.DecisionID)
			if err != nil {
				return err
			}
			old, err := within.oldClaim(ctx, one.DecisionID)
			if err != nil {
				return err
			}
			proposal := Proposal{
				Place: *place, Outcome: old.Outcome,
				Reasoning: one.Reasoning, By: subject.ID,
				// Always. A judgment whose versions moved is a
				// fresh claim about code nobody has looked at,
				// however confident whoever carried it was —
				// and seeding a new line says reasoning
				// travels and conclusions do not.
				NeedsApproval: true,
				SelectedBy:    "carried from another line",
			}
			if old.Justification != nil {
				proposal.Justification = Justification(*old.Justification)
			}
			if old.Mitigation != nil {
				proposal.Mitigation = *old.Mitigation
			}
			if old.FixedVersion != nil {
				proposal.FixedVersion = *old.FixedVersion
			}
			if old.DeferredUntil != nil {
				// Carried as it was, not extended. Somebody agreeing to this
				// is agreeing to a date, and quietly moving it forward would
				// be the tool making the judgment it is asking for.
				until := *old.DeferredUntil
				proposal.DeferredUntil = &until
			}
			// The same check every other write path makes. This one built a
			// proposal and went straight to the writer, so nothing asked
			// whether what it was carrying could be said at all — a dated
			// judgment landed on a line built once, which is the case the
			// rule exists to refuse, and a commitment arrived with the date
			// left behind.
			if err := proposal.valid(s.now()); err != nil {
				return fmt.Errorf("carry decision %d: %w", one.DecisionID, err)
			}
			// The inner form, because this is already inside a transaction:
			// carrying six judgments is one act, and half of it landing is a
			// line nobody can tell from one somebody chose that way.
			claim, err := within.newClaim(ctx, FindingClaim, subject.ID, nil,
				"carried from another line", proposal)
			if err != nil {
				return fmt.Errorf("carry decision %d: %w", one.DecisionID, err)
			}
			if _, err := within.propose(ctx, claim, proposal); err != nil {
				return fmt.Errorf("carry decision %d: %w", one.DecisionID, err)
			}
			carried++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return carried, nil
}

// placeOnLine is where a carried judgment lands: the same issue at the same
// place, at whatever versions the new line holds.
func (s *Store) placeOnLine(ctx context.Context, toTarget, decisionID int64) (*Place, error) {
	var row struct {
		ProductID       int64  `bun:"product_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		PlaceIdentity   string `bun:"place_identity"`
		Visibility      string `bun:"visibility"`
		Component       string `bun:"component_now"`
		Consumer        string `bun:"consumer_now"`
		// OnTag as an integer, because the four engines spell a boolean
		// three ways and a CASE returning 1 or 0 reads the same on all of
		// them.
		OnTag int `bun:"on_tag"`
	}
	err := s.db.NewSelect().
		TableExpr(`decision AS "de"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`de.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`de.place_identity AS "place_identity"`).
		ColumnExpr(`COALESCE((SELECT MIN(f.visibility) FROM "finding" AS "f"
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS "visibility"`, toTarget).
		ColumnExpr(`COALESCE((SELECT MIN(`+finding.ComponentUpstreamExpr+`) FROM "finding" AS "f"
			JOIN "component" AS "c" ON c.id = f.component_id
			LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS "component_now"`, toTarget).
		ColumnExpr(`COALESCE((SELECT MIN(`+finding.ConsumerUpstreamExpr+`) FROM "finding" AS "f"
			JOIN "component" AS "c" ON c.id = f.component_id
			LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS "consumer_now"`, toTarget).
		// Whether the line being carried onto was built once. It is a fact
		// about the target rather than about the decision, and leaving it
		// off made every carried place read as a branch — so the rule that
		// refuses a dated judgment on a tag could not fire here however
		// often it was asked.
		ColumnExpr(`(SELECT CASE WHEN st.kind = ? THEN 1 ELSE 0 END
			FROM "target" AS "tg" JOIN "stream" AS "st" ON st.id = tg.stream_id
			WHERE tg.id = ?) AS "on_tag"`, catalog.Tag, toTarget).
		Where("de.id = ?", decisionID).
		Scan(ctx, &row)
	if err != nil {
		return nil, fmt.Errorf("read where a carried judgment lands: %w", err)
	}
	return &Place{
		ProductID: row.ProductID, VulnerabilityID: row.VulnerabilityID,
		PlaceIdentity:     row.PlaceIdentity,
		Visibility:        access.AsVisibility(row.Visibility),
		ComponentUpstream: row.Component, ConsumerUpstream: row.Consumer,
		OnTag: row.OnTag == 1,
	}, nil
}

// oldClaim is what the judgment being carried actually said.
func (s *Store) oldClaim(ctx context.Context, decisionID int64) (*Claim, error) {
	row := new(Decision)
	// With its argument, which is what is being carried: the row says where
	// the old judgment landed, and the claim says what it was.
	if err := s.db.NewSelect().Model(row).Relation("Claim").
		Where("de.id = ?", decisionID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the judgment being carried: %w", err)
	}
	return row.Claim, nil
}
