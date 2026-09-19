package notify

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Work that has stopped moving.
//
// They are conditions because of what is wrong with each: nothing has happened.
// No message driven by an event can ever report that, so what goes quietly
// wrong in a triage workflow — a claim nobody approves, a claim sent back that
// nobody revises, a deferral running out, a team's queue nobody empties, a
// report nobody answered — is invisible to a tool that reports only what
// somebody did.
//
// Each clears by the thing happening, which is the conditions clearing, events
// acknowledged shape: nobody dismisses these, the world does.
//
// **Who hears follows who may read and act**, and it differs by
// condition rather than being one rule. A claim waiting is the approver's to
// answer, so it goes to whoever may approve it and never to its proposer, who
// cannot approve their own. A claim sent back and a deferral ending
// are the proposer's own turn, so they go to the proposer. A team's queue goes
// to the team, because the whole point of the condition is that it belongs to
// nobody in particular.
//
// **Read afresh every sweep and never remembered.** The alternative is a
// notification written when a claim is proposed and cleared when it is
// approved, which needs every path that approves, withdraws, sends back or
// lapses a claim to remember to clear it — and the one that forgets leaves
// somebody being told about work that was finished a month ago.

// waitingClaims is every claim that has been waiting on a second person for
// longer than this deployment allows, against the people who could answer it.
//
// One per claim, which is the unit an approver works at: a judgment over sixty
// places is one thing to read and one thing to agree to, and sixty alerts
// about it would be the review queue's own defect arriving by mail.
//
// Sent-back claims are excluded, because those are not waiting on an approver
// at all — they have their own condition below, aimed at the other person.
func (w *Watch) waitingClaims(ctx context.Context) (map[int64][]Holds, error) {
	after, err := setting.NewStore(w.db).Duration(ctx,
		setting.WaitingAfter, setting.DefaultWaitingAfter)
	if err != nil {
		return nil, fmt.Errorf("read how long a claim may wait: %w", err)
	}
	if after <= 0 {
		return nil, nil
	}
	since := time.Now().UTC().Add(-after)

	var rows []struct {
		ClaimID     int64     `bun:"claim_id"`
		DecisionID  int64     `bun:"decision_id"`
		ProductID   int64     `bun:"product_id"`
		Product     string    `bun:"product"`
		ProposedBy  int64     `bun:"proposed_by"`
		ProposedAt  time.Time `bun:"proposed_at"`
		Rows        int       `bun:"rows_written"`
		PrivateRows int       `bun:"private_rows"`
	}
	err = w.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "product" AS "p" ON p.id = de.product_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`de.proposed_by AS "proposed_by"`).
		ColumnExpr(`MIN(de.id) AS "decision_id"`).
		ColumnExpr(`MIN(p.name) AS "product"`).
		ColumnExpr(`MIN(de.proposed_at) AS "proposed_at"`).
		ColumnExpr(`COUNT(*) AS "rows_written"`).
		// Counted rather than taken from an aggregate over the word itself. A
		// visibility is a name and MIN over names would be answering "is any
		// of this private" by alphabetical accident.
		ColumnExpr(`SUM(CASE WHEN de.visibility = ? THEN 1 ELSE 0 END) AS "private_rows"`,
			access.Private).
		Where("de.state = ?", triage.Proposed).
		Where("de.needs_approval = ?", true).
		Where("de.sent_back_at IS NULL").
		Where("de.proposed_at <= ?", since).
		GroupExpr("de.claim_id, de.product_id, de.proposed_by").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is waiting on a second person: %w", err)
	}

	reach, err := w.whoActs(ctx)
	if err != nil {
		return nil, err
	}
	out, err := w.everybody(ctx, ClaimWaiting, reach)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	for _, row := range rows {
		private := row.PrivateRows > 0
		days := int(now.Sub(row.ProposedAt).Hours() / 24)
		holds := Holds{
			About: identify(fmt.Sprintf("claim-waiting %d", row.ClaimID)),
			Body: fmt.Sprintf("A claim in %s has been waiting %s for a second person. "+
				"It covers %s and takes effect only once somebody agrees to it.",
				row.Product, plainly(days), rowsWritten(row.Rows)),
			Link:    "/review-queue",
			Private: private,
			// A claim is one product and, in bulk, many issues, so it names
			// the product and no single issue.
			ProductID: &row.ProductID,
		}
		for personID, per := range reach {
			// Never its own proposer: approving your own claim is refused, so
			// telling them it is waiting is telling them about work they are
			// not allowed to do.
			if personID == row.ProposedBy {
				continue
			}
			at := per[row.ProductID]
			if !at.approves || !at.public() || (private && !at.private()) {
				continue
			}
			out[personID] = append(out[personID], holds)
		}
	}
	return out, nil
}

// sentBackWaiting is every claim an approver asked more of and nobody has
// touched since, against the person who has to answer.
//
// It is invisible on every screen there is, which is why it needs saying at
// all: the review queue's own tab lists claims waiting on somebody else, and a
// sent-back claim is waiting on its author. What told them was one event, at
// the moment it was sent back, and an event is exactly what cannot
// report that it has since been ignored.
func (w *Watch) sentBackWaiting(ctx context.Context) (map[int64][]Holds, error) {
	after, err := setting.NewStore(w.db).Duration(ctx,
		setting.SentBackAfter, setting.DefaultSentBackAfter)
	if err != nil {
		return nil, fmt.Errorf("read how long a sent-back claim may sit: %w", err)
	}
	if after <= 0 {
		return nil, nil
	}
	since := time.Now().UTC().Add(-after)

	var rows []struct {
		ClaimID     int64     `bun:"claim_id"`
		ProductID   int64     `bun:"product_id"`
		Product     string    `bun:"product"`
		ProposedBy  int64     `bun:"proposed_by"`
		SentBackAt  time.Time `bun:"sent_back_at"`
		PrivateRows int       `bun:"private_rows"`
	}
	err = w.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "product" AS "p" ON p.id = de.product_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`de.proposed_by AS "proposed_by"`).
		ColumnExpr(`MIN(p.name) AS "product"`).
		ColumnExpr(`MIN(de.sent_back_at) AS "sent_back_at"`).
		ColumnExpr(`SUM(CASE WHEN de.visibility = ? THEN 1 ELSE 0 END) AS "private_rows"`,
			access.Private).
		Where("de.state = ?", triage.Proposed).
		Where("de.sent_back_at IS NOT NULL").
		Where("de.sent_back_at <= ?", since).
		GroupExpr("de.claim_id, de.product_id, de.proposed_by").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what was sent back and left: %w", err)
	}

	reach, err := w.whoActs(ctx)
	if err != nil {
		return nil, err
	}
	out, err := w.everybody(ctx, SentBackWaiting, reach)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	for _, row := range rows {
		private := row.PrivateRows > 0
		at := reach[row.ProposedBy][row.ProductID]
		// A proposer who has since lost the reading that made the claim
		// possible hears nothing. The condition is about a finding, and an
		// alert is not a way back in.
		if !at.public() || (private && !at.private()) {
			continue
		}
		days := int(now.Sub(row.SentBackAt).Hours() / 24)
		out[row.ProposedBy] = append(out[row.ProposedBy], Holds{
			About: identify(fmt.Sprintf("sent-back-waiting %d", row.ClaimID)),
			Body: fmt.Sprintf("A claim of yours in %s was sent back %s ago and has not "+
				"been revised. It applies to nothing until it is.",
				row.Product, plainly(days)),
			Link:      "/review-queue?tab=mine",
			Private:   private,
			ProductID: &row.ProductID,
		})
	}
	return out, nil
}

// deferralsEnding is every standing deferral whose date is coming, against the
// person who asked for it.
//
// Before the date rather than on it, for the same reason an embargo is said
// early: what follows the date is the finding arriving back in
// somebody's queue as work that is now late, and the whole value of the
// warning is the time it leaves to do something else instead.
func (w *Watch) deferralsEnding(ctx context.Context) (map[int64][]Holds, error) {
	lead, err := setting.NewStore(w.db).Duration(ctx,
		setting.DeferralLead, setting.DefaultDeferralLead)
	if err != nil {
		return nil, fmt.Errorf("read how much warning a deferral gets: %w", err)
	}
	if lead <= 0 {
		return nil, nil
	}
	now := time.Now().UTC()
	standing, held := finding.InForce()

	var rows []struct {
		ClaimID     int64     `bun:"claim_id"`
		ProductID   int64     `bun:"product_id"`
		Product     string    `bun:"product"`
		ProposedBy  int64     `bun:"proposed_by"`
		Until       time.Time `bun:"until"`
		Places      int       `bun:"places"`
		PrivateRows int       `bun:"private_rows"`
	}
	err = w.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "product" AS "p" ON p.id = de.product_id`).
		// The argument, which is where the date lives.
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		ColumnExpr(`de.claim_id AS "claim_id"`).
		ColumnExpr(`de.product_id AS "product_id"`).
		ColumnExpr(`de.proposed_by AS "proposed_by"`).
		ColumnExpr(`MIN(p.name) AS "product"`).
		ColumnExpr(`MIN(cl.deferred_until) AS "until"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		ColumnExpr(`SUM(CASE WHEN de.visibility = ? THEN 1 ELSE 0 END) AS "private_rows"`,
			access.Private).
		// Standing only. A deferral that has been withdrawn or has lapsed is
		// not one whose end anybody is waiting for — a lapsed one is already
		// back in the queue, which is the thing this exists to give notice of.
		// Nor is one still waiting for a second person: every clause of the
		// notice would be false, and it would arrive beside the message saying
		// the claim applies to nothing until somebody agrees.
		Where("de.live_key IS NOT NULL").
		Where(standing, held...).
		Where("cl.outcome = ?", triage.Deferred).
		Where("cl.deferred_until IS NOT NULL").
		Where("cl.deferred_until > ?", now).
		Where("cl.deferred_until <= ?", now.Add(lead)).
		GroupExpr("de.claim_id, de.product_id, de.proposed_by").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which deferrals are running out: %w", err)
	}

	reach, err := w.whoActs(ctx)
	if err != nil {
		return nil, err
	}
	out, err := w.everybody(ctx, DeferralEnding, reach)
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		private := row.PrivateRows > 0
		at := reach[row.ProposedBy][row.ProductID]
		if !at.public() || (private && !at.private()) {
			continue
		}
		out[row.ProposedBy] = append(out[row.ProposedBy], Holds{
			About: identify(fmt.Sprintf("deferral-ending %d", row.ClaimID)),
			Body: fmt.Sprintf("A deferral of yours in %s ends on %s, covering %s. "+
				"On that date it stops applying and the finding is open again.",
				row.Product, row.Until.Format(time.DateOnly), rowsWritten(row.Places)),
			Link:      "/review-queue?tab=mine",
			Private:   private,
			ProductID: &row.ProductID,
		})
	}
	return out, nil
}

// queuesUntaken is every team queue holding work nobody has taken, against the
// people on that team.
//
// **One condition per team and product rather than per finding**, which is the
// one place these four differ in shape. The others are somebody's action —
// a claim is one thing a person did — and this is a population: a routing rule
// places thousands of findings in a single sweep, so a notification
// each would be the estate arriving in a notification area. What somebody has
// to know is that their team's queue has stopped being emptied, and a count
// says that.
//
// **Undecided only**, by the same test every other screen uses for it: work
// that has been argued about is not sitting still, whether or not anybody has
// closed the finding.
//
// **To the team, and only to those on it who may read what is in it.** A team
// is a queue rather than a holding, so there is nobody it is
// individually addressed to; a member who cannot read undisclosed work is not
// told that undisclosed work is waiting, which is the same rule that decides
// whether a queue may hold it at all.
func (w *Watch) queuesUntaken(ctx context.Context) (map[int64][]Holds, error) {
	after, err := setting.NewStore(w.db).Duration(ctx,
		setting.QueuedAfter, setting.DefaultQueuedAfter)
	if err != nil {
		return nil, fmt.Errorf("read how long work may sit in a queue: %w", err)
	}
	if after <= 0 {
		return nil, nil
	}
	since := time.Now().UTC().Add(-after)

	var rows []struct {
		TeamID      int64  `bun:"team_id"`
		Team        string `bun:"team"`
		TeamName    string `bun:"team_name"`
		ProductID   int64  `bun:"product_id"`
		Product     string `bun:"product"`
		Waiting     int    `bun:"waiting"`
		PrivateRows int    `bun:"private_rows"`
	}
	// One row per issue in a component, which is the unit every other list
	// of work counts in: one flaw in a kernel is one thing to deal with
	// and dozens of finding rows.
	work := w.db.NewSelect().
		Distinct().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Join(`JOIN "team" AS "tm" ON tm.party_id = f.assigned_to`).
		ColumnExpr(`tm.id AS "team_id"`).
		ColumnExpr(`tm.display_name AS "team_display"`).
		ColumnExpr(`tm.name AS "team_name"`).
		ColumnExpr(`st.product_id AS "product_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`f.visibility AS "visibility"`).
		Where("f.closed_at IS NULL").
		Where("f.assigned_at IS NOT NULL").
		Where("f.assigned_at <= ?", since).
		Where("tm.retired_at IS NULL").
		Where("NOT EXISTS (?)", w.db.NewSelect().
			TableExpr(`"decision" AS "de"`).
			ColumnExpr("1").
			Where("de.product_id = st.product_id").
			Where("de.vulnerability_id = f.vulnerability_id").
			Where("de.place_identity = f.place_identity").
			Where("de.live_key IS NOT NULL").
			Where(finding.KeyMatches))

	err = w.db.NewSelect().
		TableExpr(`(?) AS "q"`, work).
		ColumnExpr(`q.team_id AS "team_id"`).
		ColumnExpr(`MIN(COALESCE(NULLIF(q.team_display, ''), q.team_name)) AS "team"`).
		// The matched name for the link and the typed one for the sentence:
		// what a screen resolves a queue by is not what somebody calls it.
		ColumnExpr(`MIN(q.team_name) AS "team_name"`).
		ColumnExpr(`q.product_id AS "product_id"`).
		ColumnExpr(`MIN(p.name) AS "product"`).
		ColumnExpr(`COUNT(*) AS "waiting"`).
		ColumnExpr(`SUM(CASE WHEN q.visibility = ? THEN 1 ELSE 0 END) AS "private_rows"`,
			access.Private).
		Join(`JOIN "product" AS "p" ON p.id = q.product_id`).
		GroupExpr("q.team_id, q.product_id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is sitting in a queue: %w", err)
	}

	reach, err := w.whoActs(ctx)
	if err != nil {
		return nil, err
	}
	out, err := w.everybody(ctx, QueueUntaken, reach)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return out, nil
	}

	rights := access.NewStore(w.db)
	for _, row := range rows {
		members, err := rights.MembersOf(ctx, row.TeamID)
		if err != nil {
			return nil, fmt.Errorf("read who is on that team: %w", err)
		}
		private := row.PrivateRows > 0
		holds := Holds{
			About: identify(fmt.Sprintf("queue-untaken %d %d", row.TeamID, row.ProductID)),
			Body: fmt.Sprintf("%s has %s waiting in %s that nobody has taken. "+
				"Work in a queue is held by nobody until somebody picks it up.",
				row.Team, itemsWaiting(row.Waiting), row.Product),
			Link:      fmt.Sprintf("/assignments?tab=people&person=%s", url.QueryEscape(row.TeamName)),
			Private:   private,
			ProductID: &row.ProductID,
		}
		for _, personID := range members {
			at := reach[personID][row.ProductID]
			if !at.public() || (private && !at.private()) {
				continue
			}
			out[personID] = append(out[personID], holds)
		}
	}
	return out, nil
}

// plainly is a number of days as somebody would say it.
//
// "0 days" is what arithmetic gives for a threshold measured in hours and is
// not something anybody says, so the shortest thing this reports is the
// smallest true one.
func plainly(days int) string {
	switch {
	case days <= 1:
		return "a day"
	case days < 14:
		return fmt.Sprintf("%d days", days)
	case days < 60:
		return fmt.Sprintf("%d weeks", days/7)
	default:
		return fmt.Sprintf("%d months", days/30)
	}
}

// rowsWritten says how much a claim covers, in the unit a decision is written
// in.
func rowsWritten(n int) string {
	if n == 1 {
		return "1 location"
	}
	return fmt.Sprintf("%d locations", n)
}

// itemsWaiting says how much is in a queue, in the unit every list of work
// uses: one issue in one component, whatever it sits at.
func itemsWaiting(n int) string {
	if n == 1 {
		return "1 piece of work"
	}
	return fmt.Sprintf("%d pieces of work", n)
}

// unanswered is every report nobody has replied to.
//
// **Raised at once rather than after a period**, unlike the four above. They
// are about work that has stopped moving, and how long is too long is a
// judgment; this is about a letter somebody sent us that nobody answered, and
// the answer to how long that may go unanswered is "not at all". Prompt
// acknowledgment is the part of coordinated disclosure a reporter judges us
// on, and it costs nothing and is missed by being nobody's job.
//
// **To whoever may read the flaw and act on it**, which for a recorded flaw
// nobody has announced is whoever may triage undisclosed work in that product.
// A report is about somebody outside this deployment and the reply goes to
// them from a person, so this reaches the people who could be that person.
func (w *Watch) unanswered(ctx context.Context) (map[int64][]Holds, error) {
	rows, err := finding.NewStore(w.db).Unacknowledged(ctx)
	if err != nil {
		return nil, err
	}
	reach, err := w.whoActs(ctx)
	if err != nil {
		return nil, err
	}
	out, err := w.everybody(ctx, Unanswered, reach)
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		who := row.ReportedBy
		if who == "" {
			who = "Somebody"
		}
		when := ""
		if row.ReceivedOn != nil {
			when = " on " + row.ReceivedOn.Format(time.DateOnly)
		}
		holds := Holds{
			About: identify(fmt.Sprintf("unanswered %d", row.VulnerabilityID)),
			Body: fmt.Sprintf("%s reported %s in %s%s and has not been answered. "+
				"Acknowledging is the part of coordinated disclosure a reporter judges, "+
				"and it is what starts the timeline the record has to evidence.",
				who, row.Identifier, row.Product, when),
			Link: fmt.Sprintf("/products/%s/findings?q=%s",
				url.QueryEscape(row.Product), url.QueryEscape(row.Identifier)),
			Private: row.Undisclosed,
			// One issue, so a collaborator brought onto that case keeps
			// reading it after the pass that wrote it.
			ProductID:       &row.ProductID,
			VulnerabilityID: &row.VulnerabilityID,
		}
		for personID, per := range reach {
			at := per[row.ProductID]
			if !at.public() || (row.Undisclosed && !at.private()) {
				continue
			}
			out[personID] = append(out[personID], holds)
		}
	}
	return out, nil
}
