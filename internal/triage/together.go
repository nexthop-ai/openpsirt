package triage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Deciding about everything at one component at once.
//
// A distinct act with its own resolution: the places are worked out from a
// component and a build rather than named, the bound is on how many places one
// action may cover, and what comes back is one claim however many it reached.

// DefaultTogetherCap is how many findings one action may claim about when
// nobody has set a limit.
//
// The same number every other bounded write falls back to, read from where the
// setting itself is declared: recording a flaw bounds what it opens by this
// too, and a finding cannot import a triage decision.
const DefaultTogetherCap = setting.DefaultTogetherCap

// allowed is what every proposal has to satisfy before any of them is written.
//
// Checked over the whole set first, because refusing halfway is the failure
// these actions exist to avoid — and the bound is on the rows about to be
// written rather than on what a caller named, since one name expands into as
// many places as the issue sits at.
func allowed(subject access.Subject, proposals []Proposal, cap int, now time.Time) error {
	if cap <= 0 {
		cap = DefaultTogetherCap
	}
	if len(proposals) > cap {
		return fmt.Errorf("that is %d findings and the limit here is %d: narrow it, "+
			"or raise the limit deliberately", len(proposals), cap)
	}
	for _, p := range proposals {
		if !mayDecideOn(subject, p.Place.ProductID, p.Place.VulnerabilityID, visibilityOf(p.Place)) {
			return ErrNotTheirs
		}
		if err := p.valid(now); err != nil {
			return err
		}
		if p.By != subject.ID {
			return fmt.Errorf("a decision is recorded as made by whoever made it")
		}
	}
	return nil
}

// TogetherAt names what one judgment covers: some issues, and the build and
// component they sit at.
//
// The places themselves are not named. A caller free to name a place would be
// choosing which decisions apply where, and would be naming rows it read
// before this ran — so they are resolved here, inside the transaction that
// writes.
type TogetherAt struct {
	TargetID         int64
	ComponentID      int64
	VulnerabilityIDs []int64
}

// resolved is a place a judgment is about to be written against, with how bad
// the issue there is judged to be.
type resolved struct {
	Place
	SeverityCenti int
}

// Together records the same judgment against many issues at one component.
//
// The transpose of grouping. One issue across many places is what a decision
// already covers; a component carrying thousands of issues — a kernel, most of
// them in drivers a given image never builds — has no answer at all, and
// without one the choices are answering two thousand findings individually,
// which nobody does, or hiding them, which is refused.
//
// One outcome, one justification, one reasoning, one approval, and a separate
// record per issue **and per place**. Each is keyed and expires on its own,
// which is what makes one action across many findings defensible rather than a
// blanket claim — and covering every place is what stops it reporting that it
// answered a consumer it left open.
//
// Everything authorization turns on is read inside the transaction that writes
// . Which product these sit in, and whether any of them is undisclosed, decide
// whether this person may make the claim at all; read before the transaction,
// they would be answers about a database that has since moved.
//
// Bounded, because one action writing an unbounded number of rows is a denial
// of service somebody triggers by accident. The bound is checked against the
// places this actually resolves to — the count somebody is asked to narrow is
// the number of rows about to be written, not the number of names they typed.
func (s *Store) Together(ctx context.Context, subject access.Subject, at TogetherAt, p Proposal,
	cap int) (claimID int64, recorded []int64, err error) {

	if len(at.VulnerabilityIDs) == 0 {
		return 0, nil, fmt.Errorf("nothing was selected, so there is nothing to claim")
	}
	if p.By != subject.ID {
		return 0, nil, fmt.Errorf("a decision is recorded as made by whoever made it")
	}

	err = s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		// Cleared on every attempt. A retry re-runs this against a database
		// that has moved, and carrying identifiers over from the attempt that
		// failed would report claims that no longer exist.
		recorded = recorded[:0]
		claimID = 0

		places, err := placesWithin(ctx, tx, subject, at)
		if err != nil {
			return err
		}
		if len(places) == 0 {
			return fmt.Errorf("%w against that component", ErrNothingOpen)
		}
		// There is always a cap (REQ-27), so an unset one is the shipped
		// number rather than none: the two siblings that take this argument
		// fill it in the same way, and this one read "zero means unbounded" —
		// which is the one reading the rule does not have.
		if cap <= 0 {
			cap = DefaultTogetherCap
		}
		if len(places) > cap {
			return fmt.Errorf("that is %d findings and the limit here is %d: narrow the "+
				"selection, or raise the limit deliberately", len(places), cap)
		}

		claim, err := within.newClaim(ctx, TogetherClaim, subject.ID, nil, p.SelectedBy, p)
		if err != nil {
			return err
		}
		claimID = claim.ID
		each := make([]Proposal, 0, len(places))
		for _, place := range places {
			if !mayDecide(subject, place.ProductID, visibilityOf(place.Place)) {
				return ErrNotTheirs
			}
			one := p
			one.Place = place.Place
			one.SeverityCenti = place.SeverityCenti
			if err := one.valid(s.now()); err != nil {
				return err
			}
			each = append(each, one)
		}
		made, err := within.proposeAll(ctx, claim, each)
		if err != nil {
			// One live claim per combination of code holds here too. A
			// selection covering something already decided is a selection
			// somebody should look at again rather than one to write around.
			if errors.Is(err, ErrAlreadyDecided) {
				return fmt.Errorf("%w: something in this selection is already decided",
					ErrAlreadyDecided)
			}
			return err
		}
		for _, one := range made {
			recorded = append(recorded, one.ID)
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return claimID, recorded, nil
}

// placesWithin reads every open place the named issues occupy at one
// component, in the transaction that is about to write against them.
//
// Narrowed to what this subject may read, like every other query here. A claim
// therefore covers every place the person making it can see, and the places
// they cannot are left open for whoever can — which is the ordinary division
// of work rather than a gap. The alternative, refusing the whole action
// because something undisclosed sits at the same component, answers a person
// who picked from the list they were shown with a bare "not found" and no way
// to tell why.
func placesWithin(ctx context.Context, tx bun.Tx, subject access.Subject,
	at TogetherAt) ([]resolved, error) {

	var rows []struct {
		ProductID         int64  `bun:"product_id"`
		VulnerabilityID   int64  `bun:"vulnerability_id"`
		PlaceIdentity     string `bun:"place_identity"`
		Visibility        string `bun:"visibility"`
		ComponentUpstream string `bun:"component_upstream"`
		ConsumerUpstream  string `bun:"consumer_upstream"`
		Published         string `bun:"published_severity"`
		Assessed          string `bun:"assessed_severity"`
		ScoreCenti        int    `bun:"score_centi"`
		OnTag             int    `bun:"on_tag"`
	}
	query := tx.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		// What this product rates the issue, which is the rating in force
		// here. The read spans products, so each row reads its own stream's.
		Join(rating.For(rating.OnStream)).
		ColumnExpr(`st.product_id AS "product_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.place_identity AS "place_identity"`).
		ColumnExpr(`f.visibility AS "visibility"`).
		ColumnExpr(finding.ComponentUpstreamExpr+` AS "component_upstream"`).
		ColumnExpr(finding.ConsumerUpstreamExpr+` AS "consumer_upstream"`).
		// The three parts of a rating rather than the published score alone.
		// The baseline stored with a claim is what a re-affirmation compares
		// today's rating against, so storing the published number where this
		// product has rated the issue lower left the comparison asking whether
		// the severity had risen past a figure nobody was working to.
		ColumnExpr(`COALESCE(v.severity, '') AS "published_severity"`).
		ColumnExpr(`COALESCE(ir.severity, '') AS "assessed_severity"`).
		ColumnExpr(`COALESCE(v.score_centi, 0) AS "score_centi"`).
		// Whether the release was built once, which decides what may be said
		// about it. As an integer rather than a boolean: the four engines
		// spell a boolean three ways.
		ColumnExpr(`MAX(CASE WHEN st.kind = ? THEN 1 ELSE 0 END) AS "on_tag"`, catalog.Tag).
		Where("f.target_id = ?", at.TargetID).
		Where("f.component_id = ?", at.ComponentID).
		Where("f.closed_at IS NULL").
		Where("f.vulnerability_id IN (?)", bun.List(at.VulnerabilityIDs)).
		GroupExpr("st.product_id, f.vulnerability_id, f.place_identity, f.visibility, " +
			"c.upstream_version, c.version, uc.upstream_version, uc.version, " +
			"v.severity, ir.severity, v.score_centi").
		OrderExpr("f.vulnerability_id, f.place_identity")
	if err := onlyDecidable(query, subject).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read where these issues sit: %w", err)
	}

	places := make([]resolved, 0, len(rows))
	for _, row := range rows {
		places = append(places, resolved{
			Place: Place{
				ProductID: row.ProductID, VulnerabilityID: row.VulnerabilityID,
				PlaceIdentity:     row.PlaceIdentity,
				Visibility:        access.AsVisibility(row.Visibility),
				ComponentUpstream: row.ComponentUpstream,
				ConsumerUpstream:  row.ConsumerUpstream,
				OnTag:             row.OnTag == 1,
			},
			SeverityCenti: finding.Rating{
				Published: row.Published, Assessed: row.Assessed, ScoreCenti: row.ScoreCenti,
			}.Score(),
		})
	}
	return places, nil
}
