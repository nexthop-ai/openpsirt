// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package obligation

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
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
	// EndsAt is the moment the incident became known, plus the window.
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
// deployment counts as it runs from that record, and every notice given.
type Entry struct {
	Standing
	Windows []Due
	Told    []Told
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
		ColumnExpr(`p.display_name AS "product_name"`).
		// Whether any finding of the issue in this product is undisclosed.
		// As an integer rather than a boolean: the four engines spell a
		// boolean three ways.
		ColumnExpr(`CASE WHEN EXISTS (SELECT 1 FROM "finding" AS "f"`+
			` JOIN "target" AS "tg" ON tg.id = f.target_id`+
			` JOIN "stream" AS "st" ON st.id = tg.stream_id`+
			` WHERE f.vulnerability_id = eh.vulnerability_id`+
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
	windows, err := s.Windows(ctx)
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
	now := s.now()
	entries := make([]Entry, 0, len(kept))
	for _, one := range kept {
		entries = append(entries, Entry{
			Standing: one,
			Windows: Running(windows, one.Record.ProductID, one.Record.KnownAt,
				told[one.Record.ID], now),
			Told: told[one.Record.ID],
		})
	}
	return entries, nil
}

// Running is every window that applies to an attack on this product, as it
// runs from one moment, with whether its warning has come, whether it has
// passed and whether a notice names it.
//
// Worked out when asked rather than stored. A window changed by an
// administrator moves every end with it, which is what changing it means. A
// window limited to other products is left out: which window applies where is
// the administrator's statement, and nothing here second-guesses it.
func Running(windows []Window, productID int64, knownAt time.Time, told []Told,
	now time.Time) []Due {
	answered := map[int64]bool{}
	for _, one := range told {
		if one.WindowID != nil {
			answered[*one.WindowID] = true
		}
	}
	out := make([]Due, 0, len(windows))
	for _, window := range windows {
		if !window.AppliesTo(productID) {
			continue
		}
		ends := window.EndsAt(knownAt)
		passed := !now.Before(ends)
		near := false
		if at, warns := window.NearAt(knownAt); warns {
			near = !passed && !now.Before(at)
		}
		out = append(out, Due{
			Window: window, EndsAt: ends,
			Passed: passed, Near: near, Answered: answered[window.ID],
		})
	}
	return out
}
