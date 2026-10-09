// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package obligation

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Standing is a record of being exploited that still stands, with the names a
// reader knows it by.
type Standing struct {
	Record triage.ExploitedHere
	// Issue is the issue as it is filed here.
	Issue string
	// Product is the name an address takes, and ProductName its spelling on
	// screen.
	Product     string
	ProductName string
	// Private says the issue is undisclosed somewhere in this product, which
	// decides who may hear about it and what may leave this deployment.
	Private bool
}

// Due is one window as it runs for one incident.
type Due struct {
	Window Window
	// Started says the window is counting. A window counting from the first
	// notice for another starts when that notice is recorded, and one counting
	// from the fix when a release named as carrying it has a stated release
	// date that has arrived. Until then it raises nothing.
	Started bool
	// StartsAt is the moment the window counts from: when the incident
	// became known, when the first notice for the window it counts from was
	// given, or the start of the earliest release date stated for a release
	// the record names as carrying the fix. Zero where there is none yet. A
	// release date still to come is a start that has not arrived, so the
	// window has a start and has not started.
	StartsAt time.Time
	// EndsAt is that moment plus the window, and zero where there is no start.
	EndsAt time.Time
	// Passed says that moment has gone.
	Passed bool
	// Near says the window's warning has come and its end has not, where it
	// names a warning.
	Near bool
	// Answered says a notice recorded against this incident names this
	// window. Whoever recorded it said so; nothing here judges whether the
	// notice met anything.
	Answered bool
}

// Entry is one incident on the shelf: the record, every window this
// deployment counts as it runs from that record, every notice given, and
// every release named as carrying the fix.
type Entry struct {
	Standing
	Windows []Due
	Told    []Told
	Fixes   []Fix
}

// Standings is every record of being exploited still standing that this
// subject may be told of, oldest known first.
//
// Narrowed record by record, each by the question that authorizes one issue
// in one product. The set is what this deployment's products have been
// attacked through and nobody has cleared, which is short. Nothing is counted
// before the narrowing, so no total says how many records exist to somebody
// shown fewer.
//
// The sweep asks as the deployment and narrows again per recipient, because
// who may act on a product is a different question from who may read it.
func (s *Store) Standings(ctx context.Context, subject access.Subject) ([]Standing, error) {
	var rows []struct {
		triage.ExploitedHere `bun:"extend"`

		Issue       string `bun:"issue"`
		Product     string `bun:"product"`
		ProductName string `bun:"product_name"`
		Private     int    `bun:"private"`
	}
	err := s.db.NewSelect().
		Model((*triage.ExploitedHere)(nil)).
		ColumnExpr("eh.*").
		ColumnExpr(`v.identifier AS "issue"`).
		ColumnExpr(`p.name AS "product"`).
		ColumnExpr(catalog.ShownExpr("p")+` AS "product_name"`).
		// Whether any finding of the issue in this product is undisclosed.
		// As an integer rather than a boolean: the four engines spell a
		// boolean three ways.
		ColumnExpr(`CASE WHEN EXISTS (SELECT 1 FROM `+finding.IssueFindings("f")+
			` JOIN "target" AS "tg" ON tg.id = f.target_id`+
			` JOIN "stream" AS "st" ON st.id = tg.stream_id`+
			` WHERE "si"."id" = eh.vulnerability_id`+
			` AND st.product_id = eh.product_id AND f.visibility = ?)`+
			` THEN 1 ELSE 0 END AS "private"`, access.Private).
		Join(`JOIN "vulnerability" AS "v" ON v.id = eh.vulnerability_id`).
		Join(`JOIN "product" AS "p" ON p.id = eh.product_id`).
		Where("eh.cleared_at IS NULL").
		Order("eh.known_at ASC", "eh.id ASC").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what stands as exploited here: %w", err)
	}
	out := make([]Standing, 0, len(rows))
	for _, row := range rows {
		allowed, err := finding.MayBeToldOfWithin(ctx, s.db, subject,
			row.ProductID, row.VulnerabilityID)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		// Whether the issue is undisclosed somewhere here is itself what an
		// embargo keeps from a reader who may not see undisclosed work. They
		// reach the record through a finding that is public, and are told
		// nothing about the ones that are not.
		private := row.Private == 1 && (subject.Reads(access.Private, row.ProductID) ||
			subject.OnCase(row.ProductID, row.VulnerabilityID))
		out = append(out, Standing{
			Record: row.ExploitedHere, Issue: row.Issue,
			Product: row.Product, ProductName: row.ProductName,
			Private: private,
		})
	}
	return out, nil
}

// Shelf is every standing record this reader may be told of, with each
// window this deployment counts and every notice given.
//
// Unpaged. A deployment where the set is long has a problem no paging would
// help with.
//
// Its own surface rather than a filter over the overdue list. A window here
// has somebody outside waiting on it, and a remediation deadline has nobody,
// so the two are never read as one list.
func (s *Store) Shelf(ctx context.Context, subject access.Subject) ([]Entry, error) {
	kept, err := s.Standings(ctx, subject)
	if err != nil {
		return nil, err
	}
	if len(kept) == 0 {
		return nil, nil
	}
	windows, err := s.Windows(ctx, subject)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(kept))
	for _, one := range kept {
		ids = append(ids, one.Record.ID)
	}
	told, err := s.ToldAbout(ctx, subject, ids)
	if err != nil {
		return nil, err
	}
	fixes, err := s.FixesOf(ctx, subject, ids)
	if err != nil {
		return nil, err
	}
	now := s.now()
	entries := make([]Entry, 0, len(kept))
	for _, one := range kept {
		fixed, _ := FixAvailable(fixes[one.Record.ID])
		entries = append(entries, Entry{
			Standing: one,
			Windows: Running(windows, one.Record.ProductID, one.Record.KnownAt,
				told[one.Record.ID], fixed, now),
			Told:  told[one.Record.ID],
			Fixes: fixes[one.Record.ID],
		})
	}
	return entries, nil
}

// Running is every window that applies to an attack on this product, as it
// runs for one incident, with whether it has started, whether its warning has
// come, whether it has passed and whether a notice names it.
//
// A window counts from the moment the attack became known, from the earliest
// notice on the incident naming the window it counts from, by the moment it
// was given rather than the order it was recorded in, or from fixed: the
// moment FixAvailable gives, and zero where it gives none.
//
// Worked out when asked rather than stored. A window changed by an
// administrator moves every end with it, which is what changing it means. A
// window limited to other products is left out: which window applies where is
// the administrator's statement, and nothing here second-guesses it.
func Running(windows []Window, productID int64, knownAt time.Time, told []Told,
	fixed, now time.Time) []Due {
	answered := map[int64]bool{}
	first := map[int64]time.Time{}
	for _, one := range told {
		if one.WindowID == nil {
			continue
		}
		answered[*one.WindowID] = true
		if at, ok := first[*one.WindowID]; !ok || one.ToldAt.Before(at) {
			first[*one.WindowID] = one.ToldAt
		}
	}
	out := make([]Due, 0, len(windows))
	for _, window := range windows {
		if !window.AppliesTo(productID) {
			continue
		}
		start, has := knownAt, true
		switch {
		case window.FromID != nil:
			start, has = first[*window.FromID]
		case window.FromFix:
			start, has = fixed, !fixed.IsZero()
		}
		if !has {
			out = append(out, Due{Window: window, Answered: answered[window.ID]})
			continue
		}
		ends := window.EndsAt(start)
		if now.Before(start) {
			out = append(out, Due{
				Window: window, StartsAt: start, EndsAt: ends, Answered: answered[window.ID],
			})
			continue
		}
		passed := !now.Before(ends)
		near := false
		if at, warns := window.NearAt(start); warns {
			near = !passed && !now.Before(at)
		}
		out = append(out, Due{
			Window: window, Started: true, StartsAt: start, EndsAt: ends,
			Passed: passed, Near: near, Answered: answered[window.ID],
		})
	}
	return out
}
