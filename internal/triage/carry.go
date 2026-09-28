// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ErrNotOffered refuses carrying a decision the preview did not offer this
// line: one that already applies here, or one covering nothing here.
var ErrNotOffered = refusal.New("is not one this line was offered")

// Carry takes chosen judgments onto a new line as claims waiting for
// agreement.
//
// It carries reasoning forward and never conclusions. Each one arrives as
// a claim needing approval, with the words from the old line to start from
// rather than to start without. A version moved, which is exactly what makes
// the old judgment stop applying — so somebody has to look at it again, and
// what is inherited is the thinking rather than the answer.
//
// Only what was offered. A caller naming a decision the preview classified
// as already applying, or as covering nothing here, is choosing something it
// was not asked about: the first has already happened and the second has
// nothing to happen to. Both are refused rather than quietly skipped, because
// a caller that got the set wrong should hear so.
//
// Bounded, like every other act answering many issues at once.
func (s *Store) Carry(ctx context.Context, subject access.Subject, fromTarget, toTarget int64,
	chosen []int64, bounds Bounds) (int, error) {

	if len(chosen) == 0 {
		return 0, nil
	}

	carried := 0
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		carried = 0

		// The claims the new line inherits, read through the same rule
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
				return fmt.Errorf("decision %d %w", id, ErrNotOffered)
			}
			wanted = append(wanted, one)
		}

		// Bounded by the reviewer's issue limit, because every judgment
		// carried waits for a second person. One chosen decision is one
		// place on the new line.
		issues := map[string]bool{}
		for _, one := range wanted {
			issues[one.Vulnerability] = true
		}
		limits, err := bounds.within(ctx, tx)
		if err != nil {
			return err
		}
		if err := limits.counted(len(issues), len(wanted), true); err != nil {
			return err
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
			// How bad the issue is judged to be here now, which is what a
			// later rise is measured from. Without it a carried claim reads
			// as made about an unrated issue.
			severity, err := within.severityOf(ctx, place.ProductID, place.VulnerabilityID)
			if err != nil {
				return err
			}
			proposal := Proposal{
				Place: *place, Outcome: old.Outcome,
				Reasoning: one.Reasoning, By: subject.ID,
				SeverityCenti: severity,
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
			// A patch promise travels with its date, carried as it was for
			// the same reason a deferral's date is. An upgrade is never
			// offered, so there is no version to carry.
			if old.CommittedTo != nil {
				by := *old.CommittedTo
				proposal.CommittedTo = &by
			}
			// The same check every other write path makes: a dated judgment
			// is refused on a line built once, as it is when proposed there.
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
	// Undisclosed where any open finding there is, disclosed where there are
	// findings and none is, and nothing where there are none.
	undisclosed, private := access.AnyPrivate("f.visibility")
	err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		// The issue the decision is read as, which is the one the new line holds.
		Join(finding.DecisionIssue).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`dv.issue_id AS "vulnerability_id"`).
		ColumnExpr(`de.place_identity AS "place_identity"`).
		ColumnExpr(`COALESCE((SELECT CASE WHEN COUNT(*) = 0 THEN NULL
				WHEN `+undisclosed+` THEN ? ELSE ? END
			FROM "finding" AS "f"
			WHERE f.target_id = ? AND f.vulnerability_id = dv.issue_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS "visibility"`, private, string(access.Private), string(access.Public), toTarget).
		Apply(versionsOnLine(toTarget, "component_now", "consumer_now")).
		// A line carried onto that was built once. It is a fact about the
		// target rather than about the decision, and the rule that refuses a
		// dated judgment on a tag reads it.
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

// versionsOnLine adds the versions a decision's place sits at on a line, as
// the two named columns: the component's and its consumer's upstream
// versions, empty where the line holds nothing open there.
//
// Both come from one finding: the first open at the place in the order both
// versions sort as text. A decision is keyed on the pair, and a place can hold
// two findings — one library vendored twice — so a minimum taken of each
// version alone can pair versions no finding holds together. Ordered on both
// and taken once, both columns read the same row.
func versionsOnLine(toTarget int64, componentAs, consumerAs string) func(*bun.SelectQuery) *bun.SelectQuery {
	first := func(expr string) string {
		return `COALESCE((SELECT ` + expr + ` FROM "finding" AS "f"
			JOIN "component" AS "c" ON c.id = f.component_id
			LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id
			WHERE f.target_id = ? AND f.vulnerability_id = dv.issue_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL
			ORDER BY ` + finding.ComponentUpstreamExpr + `, ` + finding.ConsumerUpstreamExpr + `
			LIMIT 1), '')`
	}
	return func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.
			ColumnExpr(first(finding.ComponentUpstreamExpr)+` AS ?`, toTarget, bun.Ident(componentAs)).
			ColumnExpr(first(finding.ConsumerUpstreamExpr)+` AS ?`, toTarget, bun.Ident(consumerAs))
	}
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

// Carried is what a new line would inherit from an existing one.
//
// Six buckets, because they need different things from a person. What
// already applies needs nothing. What moved needs a fresh answer, and gets the
// old reasoning to start from. A postponement is a scheduling judgment about a
// release rather than a claim about code, so it is offered separately. A
// judgment whose date has gone by sits at a place the new line still has and
// cannot be carried. A promised upgrade is planned from its component. And
// what covers nothing there is left behind.
type Carried struct {
	// Applying reach the new line by matching. Nothing to choose.
	Applying int
	// Moved held a claim at a version the new line does not have. Each comes
	// across as a proposal carrying the old words — never as a decision,
	// because the version moved and the old conclusion is not a conclusion
	// about the new code.
	Moved []Inherited
	// Postponed were deferrals. "Not this sprint" was about that sprint, and
	// carrying it silently gives a new line expiry dates nobody chose.
	Postponed []Inherited
	// Expired is how many sit at a place the new line still holds, as a
	// deferral or a promise whose date has gone by. Carried keeps the date,
	// so none of them can be carried, and each leaves a finding there with
	// no answer.
	Expired int
	// Upgrades is how many promised upgrades moved. An upgrade covers a
	// component in the releases it names and records what each of them is
	// waiting on, which a claim carried onto one place cannot write, so each
	// is planned again from the component.
	Upgrades int
	// Absent is how many cover nothing in the new line at all.
	Absent int
}

// Inherited is one claim a new line could take on.
type Inherited struct {
	DecisionID    int64
	Vulnerability string
	Component     string
	Outcome       Outcome
	Was           string
	Now           string
	Reasoning     string
	// DeferredDays is how long this has already been put off, across every
	// line it has been carried through. The number that decides whether
	// carrying it again is reasonable.
	DeferredDays int
}

// WouldCarry reports what a new line would inherit from an existing one,
// without changing anything.
//
// Asked before a line is created, because the answer is what somebody is
// agreeing to — and a carry that happened silently is the one nobody reviews.
func (s *Store) WouldCarry(ctx context.Context, subject access.Subject,
	fromTarget, toTarget int64) (*Carried, error) {

	if subject.Kind != access.Person {
		return nil, ErrNotTheirs
	}

	// productID is which product this is about, read from the build rather
	// than taken from the caller. Decisions are selected by product as well as
	// by live key and place: a place is a hash of component names carrying no
	// product, so a shared distribution package matches across products, and
	// the reasoning of undisclosed claims elsewhere would come back.
	var productID int64
	if err := s.db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("st.product_id").
		Where("tg.id = ?", toTarget).
		Scan(ctx, &productID); err != nil {
		return nil, fmt.Errorf("look up which product this line belongs to: %w", err)
	}
	var readable []access.Visibility
	for _, v := range []access.Visibility{access.Public, access.Private} {
		if mayDecide(subject, productID, v) {
			readable = append(readable, v)
		}
	}
	if len(readable) == 0 {
		return nil, ErrNotTheirs
	}

	var rows []struct {
		DecisionID    int64  `bun:"decision_id"`
		Vulnerability string `bun:"vulnerability"`
		Component     string `bun:"component"`
		Outcome       string `bun:"outcome"`
		Was           string `bun:"was"`
		Now           string `bun:"now_at"`
		ConsumerWas   string `bun:"consumer_was"`
		ConsumerNow   string `bun:"consumer_now"`
		Reasoning     string `bun:"reasoning"`
		StillThere    bool   `bun:"still_there"`
		RanOut        bool   `bun:"ran_out"`
		// Carried so a postponement can be told how long it has already run.
		VulnerabilityID int64  `bun:"vulnerability_id"`
		PlaceIdentity   string `bun:"place_identity"`
	}
	err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		// The issue each decision is read as, which is the one the new line holds.
		Join(finding.DecisionIssue).
		Join(`JOIN "vulnerability" AS "v" ON v.id = dv.issue_id`).
		// The argument, which is where the outcome lives.
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		Join(`LEFT JOIN "claim_revision" AS "dr" ON dr.id = cl.revision_id`).
		ColumnExpr(`de.id AS "decision_id"`).
		ColumnExpr(`dv.issue_id AS "vulnerability_id"`).
		ColumnExpr(`de.place_identity AS "place_identity"`).
		ColumnExpr(`v.identifier AS "vulnerability"`).
		ColumnExpr(`COALESCE(de.component_upstream_version, '') AS "was"`).
		ColumnExpr(`cl.outcome AS "outcome"`).
		ColumnExpr(`COALESCE(dr.body, '') AS "reasoning"`).
		// The new line's contents at that place, if anything.
		ColumnExpr(`COALESCE((SELECT MIN(c.name) FROM "finding" AS "f"
			JOIN "component" AS "c" ON c.id = f.component_id
			WHERE f.target_id = ? AND f.vulnerability_id = dv.issue_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS "component"`, toTarget).
		// Both versions, because a decision is keyed on both: a build whose
		// consumer alone has moved is one the claim does not reach, and the
		// finding surfaces unanswered.
		Apply(versionsOnLine(toTarget, "now_at", "consumer_now")).
		ColumnExpr(`COALESCE(de.consumer_upstream_version, '') AS "consumer_was"`).
		ColumnExpr(`EXISTS (SELECT 1 FROM "finding" AS "f"
			WHERE f.target_id = ? AND f.vulnerability_id = dv.issue_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL)
			AS "still_there"`, toTarget).
		// A date it carries that has already gone by, either of them.
		ColumnExpr(`(COALESCE(cl.deferred_until, cl.committed_to) IS NOT NULL
			AND COALESCE(cl.deferred_until, cl.committed_to) <= ?) AS "ran_out"`, s.now()).
		Where("de.live_key IS NOT NULL").
		Where("de.product_id = ?", productID).
		Where("de.visibility IN (?)", bun.List(readable)).
		Where(`EXISTS (SELECT 1 FROM "finding" AS "g"
			WHERE g.target_id = ? AND g.vulnerability_id = dv.issue_id
			  AND g.place_identity = de.place_identity)`, fromTarget).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what a new line would inherit: %w", err)
	}

	carried := &Carried{}
	var postponed []at
	for _, row := range rows {
		if !row.StillThere {
			carried.Absent++
			continue
		}
		if row.Was == row.Now && row.ConsumerWas == row.ConsumerNow {
			// The versions match, so it reaches the new line by matching.
			// Offering it would ask somebody to agree to something that has
			// already happened.
			carried.Applying++
			continue
		}
		one := Inherited{
			DecisionID: row.DecisionID, Vulnerability: row.Vulnerability,
			Component: row.Component, Outcome: Outcome(row.Outcome),
			Was: row.Was, Now: row.Now, Reasoning: row.Reasoning,
		}
		// Anything the write would refuse is not offered. A carried judgment
		// keeps its date rather than having it quietly moved forward, so a
		// deferral that has already run out and a promise whose date has
		// gone by cannot be carried at all — and offering one is offering
		// something the act behind the button turns down.
		if row.RanOut {
			carried.Expired++
			continue
		}
		if Outcome(row.Outcome) == UpgradeNeeded {
			carried.Upgrades++
			continue
		}
		if Outcome(row.Outcome) == Deferred {
			postponed = append(postponed, at{row.VulnerabilityID, row.PlaceIdentity})
			carried.Postponed = append(carried.Postponed, one)
			continue
		}
		carried.Moved = append(carried.Moved, one)
	}

	// The length each postponement has already run. Somebody agreeing to carry
	// a deferral into a new line is agreeing to however long it has been put
	// off in total, not to the months the new one asks for — and four
	// consecutive carries of "not this release" are a decision nobody made.
	already, err := s.deferredSoFarAt(ctx, productID, postponed)
	if err != nil {
		return nil, err
	}
	for i := range carried.Postponed {
		carried.Postponed[i].DeferredDays = int(already[postponed[i]].Hours() / 24)
	}
	return carried, nil
}

// at is one place a decision was made about.
type at struct {
	vulnerability int64
	place         string
}

// deferredSoFarAt totals how long each of these places has been put off, in
// one statement rather than one per row.
//
// The arithmetic happens here rather than in SQL: subtracting one timestamp
// from another and summing the result has no portable spelling, and the rows
// are already being read.
func (s *Store) deferredSoFarAt(ctx context.Context, productID int64, places []at) (map[at]time.Duration, error) {
	total := map[at]time.Duration{}
	if len(places) == 0 {
		return total, nil
	}
	issues := make([]int64, 0, len(places))
	identities := make([]string, 0, len(places))
	wanted := make(map[at]bool, len(places))
	for _, place := range places {
		if wanted[place] {
			continue
		}
		wanted[place] = true
		issues = append(issues, place.vulnerability)
		identities = append(identities, place.place)
	}

	var deferrals []Decision
	if err := s.db.NewSelect().Model(&deferrals).Relation("Claim").
		Column("vulnerability_id", "place_identity", "proposed_at", "state", "ended_at").
		Where("de.product_id = ?", productID).
		Where(finding.FiledUnderAny("de.vulnerability_id"), bun.List(issues)).
		Where("de.place_identity IN (?)", bun.List(identities)).
		Where("claim.outcome = ?", Deferred).
		// Withdrawn ones for the span they were in force, as the threshold
		// counts them.
		Where("claim.deferred_until IS NOT NULL").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read how long these have been put off: %w", err)
	}
	// Keyed by the issue each deferral is read as, which is how the places
	// were asked for.
	filed := make([]int64, 0, len(deferrals))
	for _, deferral := range deferrals {
		filed = append(filed, deferral.VulnerabilityID)
	}
	issueOf, err := finding.IssuesOf(ctx, s.db, filed)
	if err != nil {
		return nil, err
	}
	for _, deferral := range deferrals {
		deferral.VulnerabilityID = issueOf[deferral.VulnerabilityID]
		key := at{deferral.VulnerabilityID, deferral.PlaceIdentity}
		// The pair of lists matches more combinations than were asked for, so
		// what was not asked for is dropped here.
		if !wanted[key] || deferral.Claim == nil || deferral.Claim.DeferredUntil == nil {
			continue
		}
		if span := heldFor(deferral); span > 0 {
			total[key] += span
		}
	}
	return total, nil
}
