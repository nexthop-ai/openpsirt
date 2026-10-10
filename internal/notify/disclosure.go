// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// The conditions about findings rather than about the tool.
//
// These three differ from the operational conditions beside them in every way
// that matters to the code: they go to a person rather than to whoever
// administers the deployment, the row they are about can be undisclosed, and
// each is narrowed by what its recipient may read. The sweep that runs them
// and the conditions about the tool's own health stay in watch.go.

// pastDisclosure is every embargo whose date has arrived with nothing decided,
// against the people who should hear about it.
//
// Administrators, and whoever holds it. Nobody else: every one of
// these is a finding nobody has announced, so the alert is a disclosure in its
// own right, and the person holding it is told only where they may read
// undisclosed work in that product — an assignment that outlived the role that
// allowed it would otherwise deliver the thing the role was withdrawn to stop.
//
// It is derived rather than remembered, so an embargo somebody extends leaves
// this list on the next sweep without anybody dismissing anything, and one
// that is disclosed leaves it because the finding stops being private.
func (w *sweep) pastDisclosure(ctx context.Context, admins []int64) (map[int64][]Holds, error) {
	return w.disclosureWithin(ctx, admins, DisclosureDue, 0)
}

// approachingDisclosure is every embargo whose date falls inside the lead time
// somebody set.
//
// Before the date, not on it. The date arriving is the last moment to act
// rather than the first useful warning, and an approver who touches disclosure
// a few times a year has no reason to open the screen that would have told
// them. In the application rather than by mail, because mail may not name an
// undisclosed issue.
func (w *sweep) approachingDisclosure(ctx context.Context, admins []int64) (map[int64][]Holds, error) {
	lead, err := setting.NewStore(w.db).Duration(ctx, setting.DisclosureLead,
		setting.DefaultDisclosureLead)
	if err != nil {
		return nil, fmt.Errorf("read how much warning to give: %w", err)
	}
	if lead <= 0 {
		lead = setting.DefaultDisclosureLead
	}
	return w.disclosureWithin(ctx, admins, DisclosureNear, lead)
}

// statementsRevised is every standing decision whose cited VEX statement has
// since been set aside.
//
// The decision stands. A publisher changing their mind does not withdraw
// somebody's judgment — a third party's claim never becomes ours — so this is
// a condition saying the ground moved under it, not an act on the decision.
//
// It clears the way every other condition here clears: when the decision stops
// standing, or when the statement it cites is current again. Nothing is
// dismissed, because nothing here is an event.
func (w *sweep) statementsRevised(ctx context.Context) (map[int64][]Holds, error) {
	var rows []struct {
		DecisionID      int64  `bun:"decision_id"`
		ProductID       int64  `bun:"product_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Product         string `bun:"product"`
		Vulnerability   string `bun:"vulnerability"`
		Publisher       string `bun:"publisher"`
		Undisclosed     bool   `bun:"undisclosed"`
	}
	undisclosed, private := access.AnyPrivate("de.visibility")
	err := w.db.NewSelect().
		TableExpr(finding.Decisions).
		Join(`JOIN "vex_statement" AS "ss" ON ss.id = de.from_statement_id`).
		Join(`JOIN "product" AS "p" ON p.id = de.product_id`).
		// The issue the decision is read as, which is the one a reader finds
		// where a merge put another name under it.
		Join(`JOIN "vulnerability" AS "v" ON v.id = dv.issue_id`).
		ColumnExpr(`MIN(de.id) AS "decision_id"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`v.id AS "vulnerability_id"`).
		ColumnExpr(`MIN(p.name) AS "product"`).
		ColumnExpr(`MIN(v.identifier) AS "vulnerability"`).
		ColumnExpr(`ss.publisher AS "publisher"`).
		ColumnExpr(undisclosed+` AS "undisclosed"`, private).
		// Standing, because a decision nobody is relying on any more is not
		// one whose evidence moving matters.
		Where("de.live_key IS NOT NULL").
		Where("de.state = ?", triage.Approved).
		// And the statement it cited is no longer what that publisher says.
		Where("ss.superseded_at IS NOT NULL").
		// Grouped exactly as the condition is identified, so one condition is
		// one row and its link does not depend on which of several came last.
		GroupExpr("de.product_id, v.id, ss.publisher").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where a publisher changed their mind: %w", err)
	}

	// Whoever may read it and act on it, which for a claim somebody approved
	// is whoever may triage that product.
	acts := w.reach

	out, err := w.everybody(ctx, StatementRevised)
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		private := row.Undisclosed
		holds := Holds{
			About: identify(fmt.Sprintf("statement-revised %d %s %s",
				row.ProductID, row.Vulnerability, row.Publisher)),
			Body: fmt.Sprintf("%s has changed what they published about %s in %s, "+
				"and a standing decision was made after reading the old statement. "+
				"The decision stands; somebody should look.",
				row.Publisher, row.Vulnerability, row.Product),
			Link:            weblink.Decision(row.DecisionID),
			Private:         private,
			ProductID:       &row.ProductID,
			VulnerabilityID: &row.VulnerabilityID,
		}
		fanOut(out, acts, row.ProductID, private, holds)
	}
	return out, nil
}

// disclosureWithin is every undisclosed finding whose date has arrived, or —
// where a lead time is given — is about to.
//
// The kind is passed in rather than assumed. One function serves both
// conditions and it seeded from the people already being told about the
// arrived one, whichever it was computing — so for the coming one, anybody who
// was neither an administrator nor currently holding the finding was absent
// from the map, was never reconciled, and their alert stood indefinitely with
// nothing able to clear it. That alert names the issue and the product.
func (w *sweep) disclosureWithin(ctx context.Context, admins []int64, kind Kind,
	lead time.Duration) (map[int64][]Holds, error) {

	var rows []struct {
		Product         string    `bun:"product"`
		Stream          string    `bun:"stream"`
		Variant         string    `bun:"variant"`
		Component       string    `bun:"component"`
		Vulnerability   string    `bun:"vulnerability"`
		ProductID       int64     `bun:"product_id"`
		VulnerabilityID int64     `bun:"vulnerability_id"`
		DiscloseAt      time.Time `bun:"disclose_at"`
		AssignedTo      *int64    `bun:"assigned_to"`
	}
	err := findingsWith(w.db.NewSelect(), false).
		ColumnExpr(`MIN(f.disclose_at) AS "disclose_at"`).
		ColumnExpr(`MIN(f.assigned_to) AS "assigned_to"`).
		Where("f.visibility = ?", access.Private).
		Where("f.closed_at IS NULL").
		Where("f.disclose_at IS NOT NULL").
		Where("f.disclose_at <= ?", time.Now().UTC().Add(lead)).
		// With a lead time given this is the *coming* ones only: what has
		// already arrived is the other condition, and one row raising both
		// would be told twice about one thing.
		Where(func() string {
			if lead > 0 {
				return "f.disclose_at > ?"
			}
			return "f.disclose_at <= ?"
		}(), time.Now().UTC()).
		GroupExpr("p.name, st.name, va.name, c.name, v.identifier, st.product_id, v.id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is past its disclosure date: %w", err)
	}
	// Note there is no early return for an empty answer. Everybody being told
	// one of these has to be handed a list either way, empty included: Reconcile makes
	// somebody's open set exactly what it is given, so an embargo that was
	// extended clears the alert it opened only because the next sweep hands
	// the same person a list without it. Returning nothing at all would leave
	// every cleared condition standing.
	people, held := w.people, w.held
	private := map[int64]map[int64]bool{}
	// The party itself. The assignment column holds a party rather than a
	// person, and a notification goes to somebody, so the two are mapped
	// in one place rather than at each use.
	whose := make(map[int64]int64, len(people))
	for _, person := range people {
		reaches := map[int64]bool{}
		for _, grant := range held[person.ID] {
			if grant.Active && (grant.Role == access.PrivateRead || grant.Role == access.PrivateTriage) {
				reaches[grant.ProductID] = true
			}
		}
		private[person.ID] = reaches
		whose[person.PartyID] = person.ID
	}

	// Everybody who is currently being told one of these, whether or not they
	// should still hear about anything. Reconcile
	// makes one person's open set exactly what it is handed, so somebody who
	// is never handed a list is never reconciled — and their alert stands
	// after the thing it was about has been answered.
	//
	// Who hears about an embargo includes whoever holds it, and work is handed
	// around: the person who held it yesterday would keep an alert about a
	// date that has since been moved, with nothing left to clear it.
	out, err := w.everybody(ctx, kind)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		// Two conditions, two identities: an embargo that is coming and one
		// that has arrived clear differently, and a single alert would go on
		// saying "coming" after the date had passed.
		about, body := "disclosure",
			row.Vulnerability+" in "+row.Product+" at "+row.Component+
				" reached its disclosure date on "+
				row.DiscloseAt.Format(time.DateOnly)+" and nothing has been decided."
		if lead > 0 {
			about = "disclosure-near"
			body = row.Vulnerability + " in " + row.Product + " at " + row.Component +
				" discloses on " +
				row.DiscloseAt.Format(time.DateOnly) +
				" and nothing has been decided. Extending it needs a second person, " +
				"and that takes time to arrange."
		}
		holds := Holds{
			// One condition per place, because the link and whoever holds the
			// work are per place.
			About: identify(about, row.Product, row.Stream, row.Variant,
				row.Vulnerability, row.Component),
			Body: body,
			Link: weblink.Finding(row.Product, row.Stream, row.Variant,
				row.Vulnerability, row.Component, ""),
			// Every one of these is about a finding nobody has
			// announced — that is what an embargo is — so what
			// leaves this deployment about it is a link and
			// nothing else.
			Private:         true,
			ProductID:       &row.ProductID,
			VulnerabilityID: &row.VulnerabilityID,
		}
		for _, admin := range admins {
			out[admin] = append(out[admin], holds)
		}
		// And whoever holds it, where they may still read undisclosed work
		// here and are not already being told as an administrator.
		if row.AssignedTo == nil {
			continue
		}
		owner, isPerson := whose[*row.AssignedTo]
		if !isPerson {
			// A party that is not a person: a team's queue, which is nobody's
			// to be told about individually.
			continue
		}
		if _, already := out[owner]; already && contains(out[owner], holds.About) {
			continue
		}
		if !private[owner][row.ProductID] {
			continue
		}
		out[owner] = append(out[owner], holds)
	}
	return out, nil
}

// contains says a person is already being told about this one.
func contains(holding []Holds, about string) bool {
	for _, h := range holding {
		if h.About == about {
			return true
		}
	}
	return false
}
