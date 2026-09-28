// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// liveDecision is a decision that still holds its key, as a merge settles it.
type liveDecision struct {
	ID              int64     `bun:"id"`
	ProductID       int64     `bun:"product_id"`
	VulnerabilityID int64     `bun:"vulnerability_id"`
	Place           string    `bun:"place_identity"`
	Component       *string   `bun:"component_upstream_version"`
	Consumer        *string   `bun:"consumer_upstream_version"`
	State           string    `bun:"state"`
	ProposedAt      time.Time `bun:"proposed_at"`
	Outcome         string    `bun:"outcome"`
}

// anyVersion is whether the claim stands at whatever versions the place holds.
func (d liveDecision) anyVersion() bool { return d.Outcome == Mismatched }

// outranks is whether one decision has more standing than another: approved
// over proposed, and otherwise the newer.
func (d liveDecision) outranks(other liveDecision) bool {
	if (d.State == "approved") != (other.State == "approved") {
		return d.State == "approved"
	}
	if !d.ProposedAt.Equal(other.ProposedAt) {
		return d.ProposedAt.After(other.ProposedAt)
	}
	return d.ID > other.ID
}

// SupersededDecision is a live decision a merge took out of force because another
// live decision stood at the same place under the other name.
type SupersededDecision struct {
	bun.BaseModel `bun:"table:decision_superseded,alias:ds"`

	ID int64 `bun:"id,pk,autoincrement"`
	// DecisionID is the decision that lapsed and StandingID the one that stands
	// in its place.
	DecisionID int64 `bun:"decision_id,notnull"`
	StandingID int64 `bun:"standing_id,notnull"`
	MergeID    int64 `bun:"merge_id,notnull"`
	// Disagreed is whether the two said different things. A disagreement is
	// told to the product's triagers.
	Disagreed bool `bun:"disagreed,notnull"`
}

// Displaced is one judgment a merge took out of force because another stood
// in its place in the same product and said something different. The
// product's triagers are told.
type Displaced struct {
	Kind      DisplacedKind
	ProductID int64
	// RecordID is the judgment that stopped standing and StandingID the one that
	// stands in its place, both of Kind.
	RecordID   int64
	StandingID int64
	MergeID    int64
}

// DisplacedKind is which sort of judgment a merge displaced.
type DisplacedKind string

// The judgments a merge settles by standing.
const (
	// DisplacedDecision is a live decision at one place.
	DisplacedDecision DisplacedKind = "decision"
	// DisplacedRating is a rating claim in one product.
	DisplacedRating DisplacedKind = "rating"
	// DisplacedAttack is a record of the product being exploited through the
	// issue.
	DisplacedAttack DisplacedKind = "exploited-here"
)

// settleDecisions leaves one live decision at each place of the merged issue,
// and holds every live decision under the key of the issue it is read as.
//
// Decisions at different places are untouched: they combine. Where one
// product and place held a live decision under each name, about the same
// versions or with either standing at any version, the one with more standing
// stays and the other lapses, with a record naming the merge and the decision
// that stands in its place. The lapse is the one a moved version makes, and
// nothing else about the decision changes.
//
// A live decision then holds its key under the issue it is read as, because
// the key is what makes one live decision per place a rule the database keeps.
// Left under the name it was filed under, a new claim about the same place
// under the issue that stands would find nothing in its way.
func (v *Vulnerabilities) settleDecisions(ctx context.Context, kept, mergeID int64, now time.Time) error {
	var live []liveDecision
	if err := v.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		ColumnExpr("de.id, de.product_id, de.vulnerability_id, de.place_identity").
		ColumnExpr("de.component_upstream_version, de.consumer_upstream_version").
		ColumnExpr("de.state, de.proposed_at, cl.outcome").
		Where(FiledUnder("de.vulnerability_id"), kept).
		Where("de.live_key IS NOT NULL").
		OrderExpr("de.id").
		Scan(ctx, &live); err != nil {
		return fmt.Errorf("read what stands about the merged issue: %w", err)
	}

	type at struct {
		product int64
		place   string
	}
	byPlace := map[at][]liveDecision{}
	var order []at
	for _, d := range live {
		key := at{d.ProductID, d.Place}
		if _, seen := byPlace[key]; !seen {
			order = append(order, key)
		}
		byPlace[key] = append(byPlace[key], d)
	}
	lapsed := map[int64]bool{}
	for _, key := range order {
		for _, set := range colliding(byPlace[key]) {
			if err := v.supersede(ctx, set, mergeID, now, lapsed); err != nil {
				return err
			}
		}
	}

	for _, d := range live {
		if lapsed[d.ID] || d.VulnerabilityID == kept {
			continue
		}
		key := LiveKey(d.ProductID, kept, d.Place, orBlank(d.Component), orBlank(d.Consumer),
			d.anyVersion())
		if _, err := v.db.NewUpdate().TableExpr(`"decision"`).
			Set(`"live_key" = ?`, key).
			Where(`"id" = ?`, d.ID).Exec(ctx); err != nil {
			return fmt.Errorf("hold decision %d under the issue it is read as: %w", d.ID, err)
		}
	}
	return nil
}

// colliding is the sets of live decisions at one place that hold one key
// under more than one name, which is what one issue holds one of.
//
// A decision standing at any version collides with another standing at any
// version. The rest collide where their versions agree. A claim at any version
// and a claim about particular versions stand side by side under one issue, so
// they stand side by side after a merge: the first is about identity and does
// not lapse to a claim about a version (REQ-25).
func colliding(here []liveDecision) [][]liveDecision {
	type held struct {
		anyVersion          bool
		component, consumer string
	}
	byVersions := map[held][]liveDecision{}
	var order []held
	for _, d := range here {
		key := held{anyVersion: true}
		if !d.anyVersion() {
			key = held{component: strings.TrimSpace(orBlank(d.Component)),
				consumer: strings.TrimSpace(orBlank(d.Consumer))}
		}
		if _, seen := byVersions[key]; !seen {
			order = append(order, key)
		}
		byVersions[key] = append(byVersions[key], d)
	}
	var sets [][]liveDecision
	for _, key := range order {
		set := byVersions[key]
		filed := map[int64]bool{}
		for _, d := range set {
			filed[d.VulnerabilityID] = true
		}
		if len(filed) > 1 {
			sets = append(sets, set)
		}
	}
	return sets
}

// supersede keeps the decision in a colliding set with the most standing and
// lapses the rest, recording why.
func (v *Vulnerabilities) supersede(ctx context.Context, set []liveDecision, mergeID int64,
	now time.Time, lapsed map[int64]bool) error {

	winner := set[0]
	for _, d := range set[1:] {
		if d.outranks(winner) {
			winner = d
		}
	}
	for _, d := range set {
		if d.ID == winner.ID {
			continue
		}
		if _, err := v.db.NewUpdate().TableExpr(`"decision"`).
			Set(`"state" = ?`, "lapsed").
			Set(`"ended_at" = ?`, now).
			Set(`"live_key" = NULL`).
			Where(`"id" = ?`, d.ID).Exec(ctx); err != nil {
			return fmt.Errorf("lapse decision %d, which a merge superseded: %w", d.ID, err)
		}
		record := &SupersededDecision{
			DecisionID: d.ID, StandingID: winner.ID, MergeID: mergeID,
			Disagreed: d.Outcome != winner.Outcome,
		}
		if _, err := v.db.NewInsert().Model(record).Exec(ctx); err != nil {
			return fmt.Errorf("record why decision %d lapsed: %w", d.ID, err)
		}
		lapsed[d.ID] = true
		if record.Disagreed {
			v.displaced = append(v.displaced, Displaced{
				Kind: DisplacedDecision, ProductID: d.ProductID,
				RecordID: d.ID, StandingID: winner.ID, MergeID: mergeID,
			})
		}
	}
	return nil
}

// settleRecords holds what a product said about the absorbed issue under the
// issue it is read as: its rating in force, its tags, and the rating claim and
// the record of being attacked that stand there.
//
// Where the kept issue already holds its own rating in force or tag in that
// product, its own stays and the absorbed issue's goes: both are derived or
// current state, and one issue carries one of each.
func (v *Vulnerabilities) settleRecords(ctx context.Context, kept int64, absorbed Vulnerability,
	mergeID int64, now time.Time) error {

	gone := absorbed.ID
	var rated []IssueRating
	if err := v.db.NewSelect().Model(&rated).
		Where("ir.vulnerability_id IN (?, ?)", kept, gone).
		Scan(ctx); err != nil {
		return fmt.Errorf("read what the merged issues are rated: %w", err)
	}
	keptRates := map[int64]bool{}
	for _, r := range rated {
		if r.VulnerabilityID == kept {
			keptRates[r.ProductID] = true
		}
	}
	for _, r := range rated {
		if r.VulnerabilityID != gone {
			continue
		}
		if keptRates[r.ProductID] {
			if _, err := v.db.NewDelete().Model((*IssueRating)(nil)).
				Where("id = ?", r.ID).Exec(ctx); err != nil {
				return fmt.Errorf("leave the kept issue's rating in force: %w", err)
			}
			continue
		}
		if _, err := v.db.NewUpdate().Model((*IssueRating)(nil)).
			Set("vulnerability_id = ?", kept).
			Where("id = ?", r.ID).Exec(ctx); err != nil {
			return fmt.Errorf("carry a rating in force to the issue it rates: %w", err)
		}
		// Everything open against the issue in that product now ranks and is
		// clocked by it, including what the kept issue held before.
		if err := rerank(ctx, v.db, r.ProductID, kept, r.Severity); err != nil {
			return err
		}
		if err := redue(ctx, v.db, r.ProductID, kept); err != nil {
			return err
		}
	}

	// A tag is a product's word on a row, kept only while it is on it, so it
	// moves with the findings it marks. One already on the kept issue's row is
	// the same word said once.
	var tags []Tag
	if err := v.db.NewSelect().Model(&tags).
		Where("ft.vulnerability_id IN (?, ?)", kept, gone).
		Scan(ctx); err != nil {
		return fmt.Errorf("read what the merged issues are marked with: %w", err)
	}
	type marked struct {
		product, component int64
		tag                string
	}
	on := map[marked]bool{}
	for _, t := range tags {
		if t.VulnerabilityID == kept {
			on[marked{t.ProductID, t.ComponentID, t.Tag}] = true
		}
	}
	for _, t := range tags {
		if t.VulnerabilityID != gone {
			continue
		}
		key := marked{t.ProductID, t.ComponentID, t.Tag}
		q := v.db.NewUpdate().Model((*Tag)(nil)).Set("vulnerability_id = ?", kept)
		if on[key] {
			if _, err := v.db.NewDelete().Model((*Tag)(nil)).
				Where("id = ?", t.ID).Exec(ctx); err != nil {
				return fmt.Errorf("take off a mark the kept issue already has: %w", err)
			}
			continue
		}
		on[key] = true
		if _, err := q.Where("id = ?", t.ID).Exec(ctx); err != nil {
			return fmt.Errorf("carry a mark to the issue it marks: %w", err)
		}
	}

	why, err := v.supersededBecause(ctx, kept, absorbed)
	if err != nil {
		return err
	}
	if err := v.settleRatingClaims(ctx, kept, gone, mergeID, now, why); err != nil {
		return err
	}
	if err := v.settleAttacks(ctx, kept, gone, mergeID, now, why); err != nil {
		return err
	}
	// A record of being attacked that now stands for the kept issue marks
	// every one of its findings in that product.
	var attacked []int64
	if err := v.db.NewSelect().TableExpr(`"exploited_here"`).
		Column("product_id").
		Where(`"live_vulnerability_id" = ?`, kept).
		Scan(ctx, &attacked); err != nil {
		return fmt.Errorf("read where the kept issue was attacked: %w", err)
	}
	for _, product := range attacked {
		if err := ExploitedHereChanged(ctx, v.db, product, kept, true); err != nil {
			return err
		}
	}
	return nil
}

// superseding is what a judgment a merge displaced records: the name of the
// issue that stands, and the reason it stopped standing.
type superseding struct {
	kept    string
	because string
}

// supersededBecause is what a judgment a merge displaced records as the reason
// it stopped standing.
func (v *Vulnerabilities) supersededBecause(ctx context.Context, kept int64,
	absorbed Vulnerability) (superseding, error) {

	var name string
	if err := v.db.NewSelect().Model((*Vulnerability)(nil)).
		Column("identifier").
		Where("vu.id = ?", kept).
		Scan(ctx, &name); err != nil {
		return superseding{}, fmt.Errorf("read what the merged issue is called: %w", err)
	}
	return superseding{kept: name,
		because: "Superseded when " + absorbed.Identifier + " merged into " + name + "."}, nil
}

// trailSuperseded records in the administration trail that a merge took one
// judgment in a product out of force, against the merge rather than a person.
func (v *Vulnerabilities) trailSuperseded(ctx context.Context, why superseding,
	productID int64, was string) error {

	var product string
	if err := v.db.NewSelect().TableExpr(`"product" AS "p"`).
		ColumnExpr("p.name").
		Where("p.id = ?", productID).
		Scan(ctx, &product); err != nil {
		return fmt.Errorf("read which product a merge superseded a judgment in: %w", err)
	}
	return trail.NewStore(v.db).RecordByMerge(ctx, trail.Merge, why.kept+" on "+product,
		trail.Said(was, true), trail.Said(why.because, true))
}

// standingClaim is a rating claim that holds its key, as a merge settles it.
type standingClaim struct {
	ID         int64     `bun:"id"`
	ProductID  int64     `bun:"product_id"`
	LiveID     int64     `bun:"live_vulnerability_id"`
	Severity   string    `bun:"severity"`
	State      string    `bun:"state"`
	ProposedAt time.Time `bun:"proposed_at"`
}

// outranks is whether one claim has more standing than another: in force over
// waiting for a second person, and otherwise the newer.
func (c standingClaim) outranks(other standingClaim) bool {
	if (c.State == AssessmentLive) != (other.State == AssessmentLive) {
		return c.State == AssessmentLive
	}
	if !c.ProposedAt.Equal(other.ProposedAt) {
		return c.ProposedAt.After(other.ProposedAt)
	}
	return c.ID > other.ID
}

// settleRatingClaims leaves one rating claim standing per product about the
// merged issue, held under the issue it is read as.
//
// Where each issue held one in a product, the one with more standing stays and
// the other is withdrawn with the merge as its reason. The rating in force is
// then worked out again from the claim that stands, and a pair that rated the
// issue differently is told to the product's triagers.
func (v *Vulnerabilities) settleRatingClaims(ctx context.Context, kept, gone, mergeID int64,
	now time.Time, why superseding) error {

	var standing []standingClaim
	if err := v.db.NewSelect().TableExpr(`"assessment"`).
		Column("id", "product_id", "live_vulnerability_id", "severity", "state", "proposed_at").
		Where(`"live_vulnerability_id" IN (?, ?)`, kept, gone).
		OrderExpr(`"id"`).
		Scan(ctx, &standing); err != nil {
		return fmt.Errorf("read the rating claims standing about the merged issue: %w", err)
	}
	byProduct := map[int64][]standingClaim{}
	var products []int64
	for _, c := range standing {
		if _, seen := byProduct[c.ProductID]; !seen {
			products = append(products, c.ProductID)
		}
		byProduct[c.ProductID] = append(byProduct[c.ProductID], c)
	}
	for _, product := range products {
		here := byProduct[product]
		winner := here[0]
		for _, c := range here[1:] {
			if c.outranks(winner) {
				winner = c
			}
		}
		for _, c := range here {
			if c.ID == winner.ID {
				continue
			}
			if _, err := v.db.NewUpdate().TableExpr(`"assessment"`).
				Set(`"state" = ?`, AssessmentWithdrawn).
				Set(`"decided_at" = ?`, now).
				Set(`"decided_by" = NULL`).
				Set(`"withdrawn_because" = ?`, why.because).
				Set(`"live_vulnerability_id" = NULL`).
				Where(`"id" = ?`, c.ID).Exec(ctx); err != nil {
				return fmt.Errorf("withdraw rating claim %d, which a merge superseded: %w", c.ID, err)
			}
			if err := v.trailSuperseded(ctx, why, product,
				"rating claim: "+c.Severity+", "+c.State); err != nil {
				return err
			}
			if c.Severity != winner.Severity {
				v.displaced = append(v.displaced, Displaced{
					Kind: DisplacedRating, ProductID: product,
					RecordID: c.ID, StandingID: winner.ID, MergeID: mergeID,
				})
			}
		}
		if winner.LiveID != kept {
			if _, err := v.db.NewUpdate().TableExpr(`"assessment"`).
				Set(`"live_vulnerability_id" = ?`, kept).
				Where(`"id" = ?`, winner.ID).Exec(ctx); err != nil {
				return fmt.Errorf("hold rating claim %d under the issue it is read as: %w", winner.ID, err)
			}
		}
		if len(here) > 1 {
			// The rating in force follows the claim that stands, and with it
			// where the product's findings sit and how long they have.
			if err := liveRating(ctx, v.db, product, kept, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

// standingAttack is a record of being attacked that holds its key, as a merge
// settles it.
type standingAttack struct {
	ID         int64     `bun:"id"`
	ProductID  int64     `bun:"product_id"`
	LiveID     int64     `bun:"live_vulnerability_id"`
	KnownAt    time.Time `bun:"known_at"`
	RecordedAt time.Time `bun:"recorded_at"`
}

// settleAttacks leaves one record of being attacked standing per product
// about the merged issue, held under the issue it is read as.
//
// Every standing record has the same standing, so where each issue held one
// in a product the newer stays and the other is cleared with the merge as its
// reason. A pair that dated the attack differently is told to the product's
// triagers, because the date is what every window after an attack counts
// from.
func (v *Vulnerabilities) settleAttacks(ctx context.Context, kept, gone, mergeID int64,
	now time.Time, why superseding) error {

	var standing []standingAttack
	if err := v.db.NewSelect().TableExpr(`"exploited_here"`).
		Column("id", "product_id", "live_vulnerability_id", "known_at", "recorded_at").
		Where(`"live_vulnerability_id" IN (?, ?)`, kept, gone).
		OrderExpr(`"id"`).
		Scan(ctx, &standing); err != nil {
		return fmt.Errorf("read the records of being attacked through the merged issue: %w", err)
	}
	byProduct := map[int64][]standingAttack{}
	var products []int64
	for _, a := range standing {
		if _, seen := byProduct[a.ProductID]; !seen {
			products = append(products, a.ProductID)
		}
		byProduct[a.ProductID] = append(byProduct[a.ProductID], a)
	}
	for _, product := range products {
		here := byProduct[product]
		winner := here[0]
		for _, a := range here[1:] {
			if a.RecordedAt.After(winner.RecordedAt) ||
				(a.RecordedAt.Equal(winner.RecordedAt) && a.ID > winner.ID) {
				winner = a
			}
		}
		for _, a := range here {
			if a.ID == winner.ID {
				continue
			}
			if _, err := v.db.NewUpdate().TableExpr(`"exploited_here"`).
				Set(`"cleared_at" = ?`, now).
				Set(`"cleared_by" = NULL`).
				Set(`"cleared_because" = ?`, why.because).
				Set(`"live_vulnerability_id" = NULL`).
				Where(`"id" = ?`, a.ID).Exec(ctx); err != nil {
				return fmt.Errorf("clear record %d of being attacked, which a merge superseded: %w", a.ID, err)
			}
			if err := v.trailSuperseded(ctx, why, product,
				"exploited here, known "+a.KnownAt.UTC().Format(time.RFC3339)); err != nil {
				return err
			}
			if !a.KnownAt.Equal(winner.KnownAt) {
				v.displaced = append(v.displaced, Displaced{
					Kind: DisplacedAttack, ProductID: product,
					RecordID: a.ID, StandingID: winner.ID, MergeID: mergeID,
				})
			}
		}
		if winner.LiveID != kept {
			if _, err := v.db.NewUpdate().TableExpr(`"exploited_here"`).
				Set(`"live_vulnerability_id" = ?`, kept).
				Where(`"id" = ?`, winner.ID).Exec(ctx); err != nil {
				return fmt.Errorf("hold record %d of being attacked under the issue it is read as: %w",
					winner.ID, err)
			}
		}
	}
	return nil
}

// orBlank reads a version that may not have been stated.
func orBlank(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
