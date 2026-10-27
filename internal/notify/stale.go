// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// Work that has stopped moving.
//
// They are conditions because of what is wrong with each: nothing has happened.
// No message driven by an event can ever report that, so what goes quietly
// wrong in a triage workflow — a decision nobody approves, a decision sent back that
// nobody revises, a deferral running out, a team's queue nobody empties, a
// report nobody answered — is invisible to a tool that reports only what
// somebody did.
//
// Each clears by the thing happening: a condition clears itself where an event
// is acknowledged, so nobody dismisses these — the world does.
//
// The people who hear follow who may read and act, and they differ by
// condition rather than being one rule. A decision waiting is the approver's to
// answer, so it goes to whoever may approve it and never to its proposer, who
// cannot approve their own. A decision sent back and a deferral ending
// are the proposer's own turn, so they go to the proposer. A team's queue goes
// to the team, because the whole point of the condition is that it belongs to
// nobody in particular.
//
// Read afresh every sweep and never remembered. The alternative is a
// notification written when a decision is proposed and cleared when it is
// approved, which needs every path that approves, withdraws, sends back or
// lapses a decision to remember to clear it — and the one that forgets leaves
// somebody being told about work that was finished a month ago.

// waitingDecisions is every decision that has been waiting on a second person for
// longer than this deployment allows, against the people who could answer it.
//
// One per decision, which is the unit an approver works at: a decision over sixty
// occurrences is one thing to read and one thing to agree to, and sixty alerts
// about it would be the review queue's own defect arriving by mail.
//
// Sent-back decisions are excluded, because those are not waiting on an approver
// at all — they have their own condition below, aimed at the other person.
func (w *sweep) waitingDecisions(ctx context.Context) (map[int64][]Holds, error) {
	after, err := setting.NewStore(w.db).Duration(ctx,
		setting.WaitingAfter, setting.DefaultWaitingAfter)
	if err != nil {
		return nil, fmt.Errorf("read how long a decision may wait: %w", err)
	}
	since := time.Now().UTC().Add(-after)

	var rows []struct {
		DecisionID           int64     `bun:"decision_id"`
		DecisionOccurrenceID int64     `bun:"decision_occurrence_id"`
		ProductID            int64     `bun:"product_id"`
		Product              string    `bun:"product"`
		ProposedBy           int64     `bun:"proposed_by"`
		ProposedAt           time.Time `bun:"proposed_at"`
		Rows                 int       `bun:"rows_written"`
		PrivateRows          int       `bun:"private_rows"`
		Internal             int       `bun:"internal_rows"`
	}
	err = decisionRollup(w.db, "rows_written").
		ColumnExpr(`MIN("de"."id") AS "decision_occurrence_id"`).
		ColumnExpr(`MIN("de"."proposed_at") AS "proposed_at"`).
		Where(`"de"."state" = ?`, triage.Proposed).
		Where(`"de"."needs_approval" = ?`, true).
		Where(`"de"."sent_back_at" IS NULL`).
		Where(`"de"."proposed_at" <= ?`, since).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is waiting on a second person: %w", err)
	}

	reach := w.reach
	out, err := w.everybody(ctx, DecisionWaiting)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	for _, row := range rows {
		split := rowsOf(row.Rows, row.PrivateRows, row.Internal)
		private, internal := split.told()
		days := int(now.Sub(row.ProposedAt).Hours() / 24)
		holds := Holds{
			// The words v0.10.0 hashed, kept: an open condition is matched by
			// this hash, and a new one would tell everybody again.
			About: identify(fmt.Sprintf("claim-waiting %d", row.DecisionID)),
			Body: fmt.Sprintf("A decision in %s has been waiting %s for a second person. "+
				"It covers %s and takes effect only once somebody agrees to it.",
				row.Product, plainly(days), rowsWritten(row.Rows)),
			Link:     weblink.ReviewQueue(),
			Private:  private,
			Internal: internal,
			// A decision is one product and, in bulk, many issues, so it names
			// the product and no single issue.
			ProductID: &row.ProductID,
		}
		for personID, per := range reach {
			// Never its own proposer: approving your own decision is refused, so
			// telling them it is waiting is telling them about work they are
			// not allowed to do.
			if personID == row.ProposedBy {
				continue
			}
			at := per[row.ProductID]
			if !at.approvesAll(split) {
				continue
			}
			out[personID] = append(out[personID], holds)
		}
	}
	if err := w.waitingRulings(ctx, since, reach, out); err != nil {
		return nil, err
	}
	return out, nil
}

// waitingRulings adds every ruling on reports that has been waiting on a
// second person as long as a decision may.
//
// The same condition as a waiting decision, because it is the same thing: one
// act setting something aside, which takes effect only once somebody else
// agrees. It reaches whoever may work the product's reports, since approving
// a ruling asks that, and never its proposer.
func (w *Watch) waitingRulings(ctx context.Context, since time.Time,
	reach map[int64]map[int64]acts, out map[int64][]Holds) error {

	var rows []struct {
		RulingID    int64     `bun:"ruling_id"`
		ProductID   int64     `bun:"product_id"`
		Product     string    `bun:"product"`
		Disposition string    `bun:"disposition"`
		ProposedBy  int64     `bun:"proposed_by"`
		ProposedAt  time.Time `bun:"proposed_at"`
		Reports     int       `bun:"reports"`
	}
	err := w.db.NewSelect().
		TableExpr(`"report_ruling" AS "rr"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "rr"."product_id"`).
		Join(`JOIN "report_ruled" AS "rd" ON "rd"."ruling_id" = "rr"."id"`).
		ColumnExpr(`"rr"."id" AS "ruling_id"`).
		ColumnExpr(`"rr"."product_id" AS "product_id"`).
		ColumnExpr(`MIN("p"."name") AS "product"`).
		ColumnExpr(`MIN("rr"."disposition") AS "disposition"`).
		ColumnExpr(`MIN("rr"."proposed_by") AS "proposed_by"`).
		ColumnExpr(`MIN("rr"."proposed_at") AS "proposed_at"`).
		ColumnExpr(`COUNT(*) AS "reports"`).
		Where(`"rr"."settled_at" IS NULL`).
		Where(`"rr"."withdrawn_at" IS NULL`).
		Where(`"rr"."proposed_at" <= ?`, since).
		GroupExpr(`"rr"."id", "rr"."product_id"`).
		Scan(ctx, &rows)
	if err != nil {
		return fmt.Errorf("read which rulings are waiting on a second person: %w", err)
	}

	now := time.Now().UTC()
	for _, row := range rows {
		days := int(now.Sub(row.ProposedAt).Hours() / 24)
		reports := "one vulnerability report"
		if row.Reports != 1 {
			reports = fmt.Sprintf("%d vulnerability reports", row.Reports)
		}
		holds := Holds{
			About: identify(fmt.Sprintf("ruling-waiting %d", row.RulingID)),
			Body: fmt.Sprintf("A ruling in %s calling %s %s has been waiting %s for a "+
				"second person. It takes effect only once somebody agrees to it.",
				row.Product, reports, strings.ReplaceAll(row.Disposition, "-", " "),
				plainly(days)),
			Link: weblink.InboxWaiting(row.Product),
			// A claim nobody has agreed to set aside is one nobody has
			// decided is safe to repeat.
			Private:   true,
			ProductID: &row.ProductID,
		}
		for personID, per := range reach {
			// Whoever may agree to it: the approver capability or the right
			// to work reports, over the right to read them, and never its
			// proposer.
			at := per[row.ProductID]
			if personID == row.ProposedBy || !at.reads(true) ||
				(!at.approves && !at.triages(true)) {
				continue
			}
			out[personID] = append(out[personID], holds)
		}
	}
	return nil
}

// sentBackWaiting is every decision an approver asked more of and nobody has
// touched since, against the person who has to answer.
//
// It is invisible on every screen there is, which is why it needs saying at
// all: the review queue's own tab lists decisions waiting on somebody else, and a
// sent-back decision is waiting on its author. What told them was one event, at
// the moment it was sent back, and an event is exactly what cannot
// report that it has since been ignored.
func (w *sweep) sentBackWaiting(ctx context.Context) (map[int64][]Holds, error) {
	after, err := setting.NewStore(w.db).Duration(ctx,
		setting.SentBackAfter, setting.DefaultSentBackAfter)
	if err != nil {
		return nil, fmt.Errorf("read how long a sent-back decision may sit: %w", err)
	}
	since := time.Now().UTC().Add(-after)

	var rows []struct {
		DecisionID  int64     `bun:"decision_id"`
		ProductID   int64     `bun:"product_id"`
		Product     string    `bun:"product"`
		ProposedBy  int64     `bun:"proposed_by"`
		SentBackAt  time.Time `bun:"sent_back_at"`
		Rows        int       `bun:"rows_written"`
		PrivateRows int       `bun:"private_rows"`
		Internal    int       `bun:"internal_rows"`
	}
	err = decisionRollup(w.db, "rows_written").
		ColumnExpr(`MIN("de"."sent_back_at") AS "sent_back_at"`).
		Where(`"de"."state" = ?`, triage.Proposed).
		Where(`"de"."sent_back_at" IS NOT NULL`).
		Where(`"de"."sent_back_at" <= ?`, since).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what was sent back and left: %w", err)
	}

	reach := w.reach
	out, err := w.everybody(ctx, SentBackWaiting)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	for _, row := range rows {
		split := rowsOf(row.Rows, row.PrivateRows, row.Internal)
		private, internal := split.told()
		at := reach[row.ProposedBy][row.ProductID]
		// A proposer who has since lost the reading that made the decision
		// possible hears nothing. The condition is about a finding, and an
		// alert is not a way back in.
		if !at.readsAll(split) {
			continue
		}
		days := int(now.Sub(row.SentBackAt).Hours() / 24)
		out[row.ProposedBy] = append(out[row.ProposedBy], Holds{
			About: identify(fmt.Sprintf("sent-back-waiting %d", row.DecisionID)),
			Body: fmt.Sprintf("A decision of yours in %s was sent back %s ago and has not "+
				"been revised. It applies to nothing until it is.",
				row.Product, plainly(days)),
			Link:      weblink.ReviewQueueMine(),
			Private:   private,
			Internal:  internal,
			ProductID: &row.ProductID,
		})
	}
	return out, nil
}

// decisionRollup is every decision occurrence read as one row per decision, product and
// proposer: the product's name, how many rows the decision wrote there under the
// alias given, and how many of them are withheld: at any visibility but
// public, so a message about them carries no detail. Each sweep adds the
// conditions and the columns of its own.
//
// A row is about an issue of the kinds decisions are made about, leads'
// rules included. A decision on a lead is internal work, counted apart so that
// its audience is the product's internal readers.
//
// The withheld rows are counted rather than taken from an aggregate over
// the word itself. A visibility is a name, and MIN over names would answer "is
// any of this private" by alphabetical accident.
func decisionRollup(db bun.IDB, counted string) *bun.SelectQuery {
	return db.NewSelect().
		TableExpr(`"decision_occurrence" AS "de"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "de"."product_id"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "de"."vulnerability_id"`).
		Where(`"vu"."kind" IN (?)`, bun.List(kind.IssuesOf(kind.Decisions.Kinds()...))).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`"de"."product_id" AS "product_id"`).
		ColumnExpr(`"de"."proposed_by" AS "proposed_by"`).
		ColumnExpr(`MIN("p"."name") AS "product"`).
		ColumnExpr(`COUNT(*) AS ?`, bun.Ident(counted)).
		ColumnExpr(access.WithheldCountAs(`"de"."visibility"`, "private_rows")).
		ColumnExpr(access.InternalCountAs(`"de"."visibility"`, "internal_rows")).
		GroupExpr(`"de"."decision_id", "de"."product_id", "de"."proposed_by"`)
}

// deferralsEnding is every standing deferral whose date is coming, against the
// person who asked for it.
//
// Before the date rather than on it, for the same reason an embargo is said
// early: what follows the date is the finding arriving back in
// somebody's queue as work that is now late, and the whole value of the
// warning is the time it leaves to do something else instead.
func (w *sweep) deferralsEnding(ctx context.Context) (map[int64][]Holds, error) {
	lead, err := setting.NewStore(w.db).Duration(ctx,
		setting.DeferralLead, setting.DefaultDeferralLead)
	if err != nil {
		return nil, fmt.Errorf("read how much warning a deferral gets: %w", err)
	}
	now := time.Now().UTC()
	standing, held := finding.InForce()

	var rows []struct {
		DecisionID  int64     `bun:"decision_id"`
		ProductID   int64     `bun:"product_id"`
		Product     string    `bun:"product"`
		ProposedBy  int64     `bun:"proposed_by"`
		Until       time.Time `bun:"until"`
		Occurrences int       `bun:"places"`
		PrivateRows int       `bun:"private_rows"`
		Internal    int       `bun:"internal_rows"`
	}
	err = decisionRollup(w.db, "places").
		// The argument, which is where the date lives.
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		ColumnExpr(`MIN("cl"."deferred_until") AS "until"`).
		// Standing only. A deferral that has been withdrawn or has lapsed is
		// not one whose end anybody is waiting for — a lapsed one is already
		// its author's to re-affirm, and they were told when it lapsed.
		// Nor is one still waiting for a second person: every clause of the
		// notice would be false, and it would arrive beside the message saying
		// the decision applies to nothing until somebody agrees.
		Where(`"de"."live_key" IS NOT NULL`).
		Where(standing, held...).
		Where(`"cl"."outcome" = ?`, triage.Deferred).
		Where(`"cl"."deferred_until" IS NOT NULL`).
		Where(`"cl"."deferred_until" > ?`, now).
		Where(`"cl"."deferred_until" <= ?`, now.Add(lead)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which deferrals are running out: %w", err)
	}

	reach := w.reach
	out, err := w.everybody(ctx, DeferralEnding)
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		split := rowsOf(row.Occurrences, row.PrivateRows, row.Internal)
		private, internal := split.told()
		at := reach[row.ProposedBy][row.ProductID]
		if !at.readsAll(split) {
			continue
		}
		out[row.ProposedBy] = append(out[row.ProposedBy], Holds{
			About: identify(fmt.Sprintf("deferral-ending %d", row.DecisionID)),
			Body: fmt.Sprintf("A deferral of yours in %s ends on %s, covering %s. "+
				"On that date it stops applying and the finding is open again.",
				row.Product, day(row.Until), rowsWritten(row.Occurrences)),
			Link:      weblink.ReviewQueueMine(),
			Private:   private,
			Internal:  internal,
			ProductID: &row.ProductID,
		})
	}
	return out, nil
}

// queuesUntaken is every team queue holding work nobody has taken, against the
// people on that team.
//
// One condition per team and product rather than per finding, which is the
// one place these four differ in shape. The others are somebody's action —
// a decision is one thing a person did — and this is a population: a routing rule
// places thousands of findings in a single sweep, so a notification
// each would be the estate arriving in a notification area. What somebody has
// to know is that their team's queue has stopped being emptied, and a count
// says that.
//
// Undecided only, by the same test every other screen uses for it: work
// that has been argued about is not sitting still, whether or not anybody has
// closed the finding.
//
// To the team, and only to those on it who may read what is in it. A team
// is a queue rather than a holding, so there is nobody it is
// individually addressed to; a member who cannot read undisclosed work is not
// told that undisclosed work is waiting, which is the same rule that decides
// whether a queue may hold it at all.
func (w *sweep) queuesUntaken(ctx context.Context) (map[int64][]Holds, error) {
	after, err := setting.NewStore(w.db).Duration(ctx,
		setting.QueuedAfter, setting.DefaultQueuedAfter)
	if err != nil {
		return nil, fmt.Errorf("read how long work may sit in a queue: %w", err)
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
	// and dozens of finding rows. Grouped rather than distinct over the
	// visibility, which would make one issue at an undisclosed occurrence and a
	// disclosed one two pieces of work; the group is withheld where any of
	// its rows is.
	kinds, kindArgs := kind.Notifications.Where(`"f"."kind"`)
	work := w.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(`JOIN "team" AS "tm" ON "tm"."party_id" = "f"."assigned_to"`).
		ColumnExpr(`"tm"."id" AS "team_id"`).
		ColumnExpr(`"tm"."display_name" AS "team_display"`).
		ColumnExpr(`"tm"."name" AS "team_name"`).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		ColumnExpr(access.WithheldCountAs(`"f"."visibility"`, "private_rows")).
		Where(kinds, kindArgs...).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."assigned_at" IS NOT NULL`).
		Where(`"f"."assigned_at" <= ?`, since).
		Where(`"tm"."retired_at" IS NULL`).
		Where("NOT EXISTS (?)", w.db.NewSelect().
			TableExpr(finding.Decisions).
			Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
			ColumnExpr("1").
			Where(finding.DecisionAt(`"st"."product_id"`)).
			Where(`"de"."live_key" IS NOT NULL`).
			Where(finding.KeyMatches)).
		GroupExpr(`"tm"."id", "tm"."display_name", "tm"."name", "st"."product_id", "f"."vulnerability_id", "f"."component_id"`)

	err = w.db.NewSelect().
		TableExpr(`(?) AS "q"`, work).
		ColumnExpr(`"q"."team_id" AS "team_id"`).
		ColumnExpr(`MIN(COALESCE(NULLIF("q"."team_display", ''), "q"."team_name")) AS "team"`).
		// The matched name for the link and the typed one for the sentence:
		// what a screen resolves a queue by is not what somebody calls it.
		ColumnExpr(`MIN("q"."team_name") AS "team_name"`).
		ColumnExpr(`"q"."product_id" AS "product_id"`).
		ColumnExpr(`MIN("p"."name") AS "product"`).
		ColumnExpr(`COUNT(*) AS "waiting"`).
		ColumnExpr(`MAX("q"."private_rows") AS "private_rows"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "q"."product_id"`).
		GroupExpr(`"q"."team_id", "q"."product_id"`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is sitting in a queue: %w", err)
	}

	reach := w.reach
	out, err := w.everybody(ctx, QueueUntaken)
	if err != nil {
		return nil, err
	}

	// The open reports a team's queue holds, in a condition of their own. A
	// report is undisclosed, so one folded into the findings' count would
	// withhold the whole queue from a member who reads only disclosed work.
	var reports []struct {
		TeamID    int64  `bun:"team_id"`
		Team      string `bun:"team"`
		TeamName  string `bun:"team_name"`
		ProductID int64  `bun:"product_id"`
		Product   string `bun:"product"`
		Waiting   int    `bun:"waiting"`
	}
	if err := w.db.NewSelect().
		TableExpr(`"flaw_report" AS "fr"`).
		Join(`JOIN "team" AS "tm" ON "tm"."party_id" = "fr"."assigned_to"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "fr"."product_id"`).
		ColumnExpr(`"tm"."id" AS "team_id"`).
		ColumnExpr(`MIN(COALESCE(NULLIF("tm"."display_name", ''), "tm"."name")) AS "team"`).
		ColumnExpr(`MIN("tm"."name") AS "team_name"`).
		ColumnExpr(`"fr"."product_id" AS "product_id"`).
		ColumnExpr(`MIN("p"."name") AS "product"`).
		ColumnExpr(`COUNT(*) AS "waiting"`).
		// Untouched only, as a finding is: one judged, or under a ruling,
		// has been acted on.
		Where(`"fr"."evaluated_at" IS NULL`).
		Where(`"fr"."vulnerability_id" IS NULL`).
		Where(`"fr"."ruling_id" IS NULL`).
		Where(`"fr"."assigned_at" <= ?`, since).
		Where(`"tm"."retired_at" IS NULL`).
		GroupExpr(`"tm"."id", "fr"."product_id"`).
		Scan(ctx, &reports); err != nil {
		return nil, fmt.Errorf("read the reports sitting in a queue: %w", err)
	}
	rights := access.NewStore(w.db)
	for _, row := range reports {
		members, err := rights.MembersOf(ctx, row.TeamID)
		if err != nil {
			return nil, fmt.Errorf("read who is on that team: %w", err)
		}
		holds := Holds{
			About: identify(fmt.Sprintf("queue-untaken-reports %d %d", row.TeamID, row.ProductID)),
			Body: fmt.Sprintf("%s has %s waiting in %s that nobody has taken.",
				row.Team, count(row.Waiting, "vulnerability report", "vulnerability reports"), row.Product),
			Link:      weblink.AssignmentsTeam(row.TeamName),
			Private:   true,
			ProductID: &row.ProductID,
			TeamID:    &row.TeamID,
		}
		for _, personID := range members {
			if reach[personID][row.ProductID].reads(true) {
				out[personID] = append(out[personID], holds)
			}
		}
	}
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
			Link:      weblink.AssignmentsTeam(row.TeamName),
			Private:   private,
			ProductID: &row.ProductID,
			TeamID:    &row.TeamID,
		}
		for _, personID := range members {
			at := reach[personID][row.ProductID]
			// Disclosed work travels with the assignment to whoever holds
			// it, so a member reading the product at any visibility may
			// take it. Withheld work needs one who reads it.
			if (private && !at.reads(true)) || (!private && !at.readsIn()) {
				continue
			}
			out[personID] = append(out[personID], holds)
		}
	}
	return out, w.leadQueuesUntaken(ctx, since, out)
}

// leadQueuesUntaken adds to what queuesUntaken tells the leads sitting in a
// team's queue that nobody has taken, one condition per team and product.
//
// A lead is one piece of work at its occurrence, however many builds it is open
// on. One handed off as a flaw is closed work for its holder, and one a decision
// stands on is being judged. Every lead it counts is internal, so it reaches
// the members who read the product's internal work and nobody else.
func (w *sweep) leadQueuesUntaken(ctx context.Context, since time.Time, out map[int64][]Holds) error {
	var rows []struct {
		TeamID    int64  `bun:"team_id"`
		Team      string `bun:"team"`
		TeamName  string `bun:"team_name"`
		ProductID int64  `bun:"product_id"`
		Product   string `bun:"product"`
		Waiting   int    `bun:"waiting"`
	}
	kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
	work := w.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		Join(`JOIN "team" AS "tm" ON "tm"."party_id" = "f"."assigned_to"`).
		ColumnExpr(`"tm"."id" AS "team_id"`).
		ColumnExpr(`"tm"."display_name" AS "team_display"`).
		ColumnExpr(`"tm"."name" AS "team_name"`).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(`"f"."occurrence_identity" AS "occurrence_identity"`).
		Where(kinds, kindArgs...).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."assigned_at" IS NOT NULL`).
		Where(`"f"."assigned_at" <= ?`, since).
		Where(`"tm"."retired_at" IS NULL`).
		Where(`NOT EXISTS (SELECT 1 FROM "lead_handoff" AS "lh"
			WHERE "lh"."product_id" = "st"."product_id" AND "lh"."occurrence_identity" = "f"."occurrence_identity")`).
		Where(`NOT EXISTS (SELECT 1 FROM "decision_occurrence" AS "dc"
			WHERE "dc"."product_id" = "st"."product_id" AND "dc"."live_key" IS NOT NULL
			AND ` + finding.DecisionFiledAt("dc", "f") + `)`).
		GroupExpr(`"tm"."id", "tm"."display_name", "tm"."name", "st"."product_id", "f"."occurrence_identity"`)

	if err := w.db.NewSelect().
		TableExpr(`(?) AS "q"`, work).
		ColumnExpr(`"q"."team_id" AS "team_id"`).
		ColumnExpr(`MIN(COALESCE(NULLIF("q"."team_display", ''), "q"."team_name")) AS "team"`).
		ColumnExpr(`MIN("q"."team_name") AS "team_name"`).
		ColumnExpr(`"q"."product_id" AS "product_id"`).
		ColumnExpr(`MIN("p"."name") AS "product"`).
		ColumnExpr(`COUNT(*) AS "waiting"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "q"."product_id"`).
		GroupExpr(`"q"."team_id", "q"."product_id"`).
		Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read which leads are sitting in a queue: %w", err)
	}

	rights := access.NewStore(w.db)
	for _, row := range rows {
		members, err := rights.MembersOf(ctx, row.TeamID)
		if err != nil {
			return fmt.Errorf("read who is on that team: %w", err)
		}
		productID, teamID := row.ProductID, row.TeamID
		holds := Holds{
			About: identify(fmt.Sprintf("lead-queue-untaken %d %d", row.TeamID, row.ProductID)),
			Body: fmt.Sprintf("%s has %s waiting in %s that nobody has taken. "+
				"Work in a queue is held by nobody until somebody picks it up.",
				row.Team, leadsWaiting(row.Waiting), row.Product),
			Link:    weblink.AssignmentsTeam(row.TeamName),
			Private: true, Internal: true,
			ProductID: &productID,
			TeamID:    &teamID,
		}
		for _, personID := range members {
			if !w.reach[personID][row.ProductID].readsInternal {
				continue
			}
			out[personID] = append(out[personID], holds)
		}
	}
	return nil
}

// leadsWaiting says how many leads wait, in the unit the lead queue counts.
func leadsWaiting(n int) string {
	if n == 1 {
		return "1 static analysis lead"
	}
	return fmt.Sprintf("%d static analysis leads", n)
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

// rowsWritten says how much a decision covers, in the unit its rows are written
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
// Raised at once rather than after a period, unlike the four above. They
// are about work that has stopped moving, and how long is too long is a
// judgment; this is about a letter somebody sent us that nobody answered, and
// the answer to how long that may go unanswered is "not at all". Prompt
// acknowledgment is the part of coordinated disclosure a reporter judges us
// on, and it costs nothing and is missed by being nobody's job.
//
// To the report's audience: the person holding it, the members of the team
// whose queue it is in, or, where nobody holds it, whoever may triage work
// nobody has announced in that product. A holder and a team member are told
// only where they read the product's reports, so the notice never names a
// report the reader is refused.
//
// Judged or not. A report that turned out to be announced work is still a
// letter a stranger sent, and reading it asks the same thing it asked
// before.
func (w *sweep) unanswered(ctx context.Context) (map[int64][]Holds, error) {
	rows, err := finding.NewStore(w.db).Unacknowledged(ctx)
	if err != nil {
		return nil, err
	}
	reach := w.reach
	out, err := w.everybody(ctx, Unanswered)
	if err != nil {
		return nil, err
	}
	held := make([]*int64, 0, len(rows))
	for _, row := range rows {
		held = append(held, row.AssignedTo)
	}
	audience, err := newReportAudience(ctx, w.db, reach, held)
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
			when = " on " + day(*row.ReceivedOn)
		}
		holds := Holds{
			About: identify(fmt.Sprintf("unanswered %d", row.VulnerabilityID)),
			Body: fmt.Sprintf("%s reported %s in %s%s and has not been answered. "+
				"The first message recorded as sent to them is the acknowledgement, "+
				"and it is what starts the timeline the record has to evidence.",
				who, row.Identifier, row.Product, when),
			Link:    weblink.ProductFindings(row.Product, row.Identifier),
			Private: row.Undisclosed,
			// One issue, so a collaborator brought onto that case keeps
			// reading it after the pass that wrote it.
			ProductID:       &row.ProductID,
			VulnerabilityID: &row.VulnerabilityID,
		}
		// A report with no issue — unjudged, or ruled something other than
		// one — has no issue to name and nobody on a case. It is named by the
		// reference it was minted with, and points at the report.
		if row.VulnerabilityID == 0 {
			holds.About = identify(fmt.Sprintf("unanswered report %d", row.ReportID))
			holds.Body = fmt.Sprintf("%s sent %s in %s%s and has not been answered. "+
				"The first message recorded as sent to them is the acknowledgement, "+
				"and it is what starts the timeline the record has to evidence.",
				who, row.Reference, row.Product, when)
			holds.Link = weblink.InboxReport(row.Product, row.Reference)
			holds.VulnerabilityID = nil
		}
		told, err := audience.of(ctx, row.ProductID, row.AssignedTo)
		if err != nil {
			return nil, err
		}
		for _, personID := range told {
			out[personID] = append(out[personID], holds)
		}
	}
	return out, nil
}
