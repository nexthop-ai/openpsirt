// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Repeated is one place that keeps being put off.
//
// A cumulative threshold already refuses a *further* deferral past a point,
// which acts on one item at a time. What that cannot show is the shape across
// everything: one item deferred three times is a judgment, and forty of them
// is a policy nobody wrote down and nobody agreed to.
type Repeated struct {
	Product       string
	ProductName   string
	Vulnerability string
	Severity      string
	// PlaceIdentity names the place rather than describing it. What it is
	// called depends on the build being looked at, and this list is not about
	// one build.
	PlaceIdentity string
	// Times is how many claims put it off, and TotalDays how long it has been
	// put off for. The two answer different questions: three short deferrals
	// and one long one are different situations, and a list carrying only one
	// of the numbers hides whichever it is not.
	Times int
	// TotalDays is how long the place was put off for, in days, with the
	// stretches its deferrals overlapped counted once. A fraction, rounded
	// where it is shown rather than where it is worked out, so nothing rounds
	// twice.
	TotalDays float64
	// Standing says a deferral is in force now rather than all of them having
	// run out. Something put off three times and now decided is history; the
	// same thing still being put off is the pattern this list is for.
	Standing bool
	// LastUntil is the furthest any of them reached.
	LastUntil time.Time
}

// DefaultRepeatedAt is how many deferrals make something worth listing.
//
// Two, because one is an ordinary judgment and the list exists for the pattern
// rather than for the act. It is a starting point rather than a rule: how many
// is too many is a judgment about a product, and the caller may ask for more.
const DefaultRepeatedAt = 2

// RepeatsPage lists places that have been deferred more than once, worst
// first, from a position in the list, with how many there are in all.
//
// Counted over the claims rather than over the findings. A deferral is
// one judgment about a place; the places fan out into as many findings as the
// component has consumers, and counting those would order the list by how far
// a component spreads through an image.
//
// Paged because a ceiling with no offset means what is past it cannot be read
// through the API at all — and this one grows with the estate, which is the
// whole subject of the report.
func (s *Store) RepeatsPage(ctx context.Context, subject access.Subject, productID int64,
	atLeast, limit, offset int) ([]Repeated, int, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second.
	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read which deferrals repeat")
	}
	if atLeast <= 0 {
		atLeast = DefaultRepeatedAt
	}
	limit = database.InBulk.Of(limit)

	var rows []struct {
		ProductID     int64      `bun:"product_id"`
		IssueID       int64      `bun:"issue_id"`
		Product       string     `bun:"product"`
		ProductName   string     `bun:"product_name"`
		Vulnerability string     `bun:"vulnerability"`
		Severity      string     `bun:"severity"`
		PlaceIdentity string     `bun:"place_identity"`
		ClaimID       int64      `bun:"claim_id"`
		ProposedAt    time.Time  `bun:"proposed_at"`
		DeferredUntil time.Time  `bun:"deferred_until"`
		State         State      `bun:"state"`
		EndedAt       *time.Time `bun:"ended_at"`
		Live          int        `bun:"live"`
	}
	// Every deferral row, grouped and added up here. How long a place was
	// put off is the stretches its deferrals held it, with overlaps counted
	// once, and a union of intervals has no portable spelling in SQL.
	q := s.db.NewSelect().
		TableExpr(finding.Decisions).
		// The issue each deferral is read as, so a place put off under two
		// names that merged is one place put off.
		Join(`JOIN "vulnerability" AS "v" ON v.id = dv.issue_id`).
		Join(`JOIN "product" AS "p" ON p.id = de.product_id`).
		// And what that product rates the issue, where it rates it anything.
		// The report is per product already, and a rating belongs to one — so
		// the word beside a repeated deferral is the word the team doing the
		// deferring holds.
		Join(rating.For(rating.OnDecision)).
		// The argument, which is where the outcome and the date live.
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		// Grouped on the product's identifier and the issue's, with the names
		// carried along as labels. Only the product's name is unique, and it
		// is not the one anybody reads, so two products a catalog displays
		// alike stay two.
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`v.id AS "issue_id"`).
		ColumnExpr(`p.name AS "product"`).
		ColumnExpr(catalog.ShownExpr("p")+` AS "product_name"`).
		ColumnExpr(`v.identifier AS "vulnerability"`).
		ColumnExpr(rating.EffectiveExpr+` AS "severity"`).
		ColumnExpr(`de.place_identity AS "place_identity"`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`de.proposed_at AS "proposed_at"`).
		ColumnExpr(`cl.deferred_until AS "deferred_until"`).
		ColumnExpr(`de.state AS "state"`).
		ColumnExpr(`de.ended_at AS "ended_at"`).
		ColumnExpr(`CASE WHEN de.live_key IS NOT NULL THEN 1 ELSE 0 END AS "live"`).
		Where("cl.outcome = ?", Deferred).
		// Withdrawn and lapsed ones counted for the span they were in force,
		// the way the threshold counts them. Left out, the report built to
		// catch withdraw-and-defer-again was blind to exactly that pattern.
		Where("cl.deferred_until IS NOT NULL")
	if productID > 0 {
		q = q.Where("de.product_id = ?", productID)
	}
	if err := readableBy(q, subject, "de").Scan(ctx, &rows); err != nil {
		return nil, 0, fmt.Errorf("read what keeps being put off: %w", err)
	}

	type place struct {
		product, issue int64
		at             string
	}
	now := s.now().UTC()
	var order []place
	found := map[place]*Repeated{}
	claims := map[place]map[int64]bool{}
	held := spans[place]{}
	for _, row := range rows {
		key := place{row.ProductID, row.IssueID, row.PlaceIdentity}
		one, seen := found[key]
		if !seen {
			one = &Repeated{
				Product: row.Product, ProductName: row.ProductName,
				Vulnerability: row.Vulnerability, Severity: row.Severity,
				PlaceIdentity: row.PlaceIdentity,
			}
			found[key] = one
			claims[key] = map[int64]bool{}
			order = append(order, key)
		}
		if row.DeferredUntil.After(one.LastUntil) {
			one.LastUntil = row.DeferredUntil
		}
		if row.Live == 1 && row.DeferredUntil.After(now) {
			one.Standing = true
		}
		// Counted over the deferrals that actually held, once per claim. One
		// taken back before it took effect put nothing off, and counting it
		// would make correcting a mistake read as avoiding the work; one
		// claim at two versions is one deferral.
		if span, ok := heldSpan(row.ProposedAt, row.DeferredUntil, row.State, row.EndedAt); ok {
			held[key] = append(held[key], span)
			claims[key][row.ClaimID] = true
		}
	}

	out := make([]Repeated, 0, len(order))
	for _, key := range order {
		one := found[key]
		one.Times = len(claims[key])
		if one.Times < atLeast {
			continue
		}
		one.TotalDays = held.total(key).Hours() / 24
		out = append(out, *one)
	}
	// The most put-off first, and then the longest: a list read from the top
	// should start with the thing somebody has avoided most. The product and
	// the place after, so a page is the same page on every engine.
	slices.SortFunc(out, func(a, b Repeated) int {
		return cmp.Or(
			cmp.Compare(b.Times, a.Times),
			cmp.Compare(b.TotalDays, a.TotalDays),
			cmp.Compare(a.Vulnerability, b.Vulnerability),
			cmp.Compare(a.Product, b.Product),
			cmp.Compare(a.PlaceIdentity, b.PlaceIdentity))
	})
	// Counted over the grouping, which is a place rather than a deferral:
	// the report's own subject is how many places keep being put off.
	total := len(out)
	if offset >= len(out) {
		return nil, total, nil
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, total, nil
}
