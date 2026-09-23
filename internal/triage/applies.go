// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Applying returns the decision standing against a place, if one is.
//
// Expiry happens here and is not a mechanism. A decision was stored under the
// versions it was a claim about; a place asks under the versions it has now.
// With a version moved the two keys stop matching and the decision simply does
// not come back — nothing sweeps, nothing expires on a timer, and there is no
// second rule that could disagree with the first.
//
// That is why only the *upstream* versions are compared. A shipped package is
// rebuilt constantly and carries a version of its own that moves each time; a
// rebuild is not somebody's reasoning becoming wrong. What changes the
// reasoning is the code changing, which is what an upstream version moving
// says.
//
// It follows that a producer which patches rather than bumps will not lapse
// decisions this way at all. That is accepted rather than worked around: a
// patch is our own change to our own build, and it would be a poor trade to
// re-ask every question every night in order to catch the few that a patch
// made stale. What compensates is that a decision's age is shown wherever it
// appears, so an old judgment looks like one.
// It takes no subject, unlike everything else read here, because the question
// is not a person's: it is whether this finding is suppressed, asked while
// recording what a scan found and while listing findings for anybody at all.
// The answer does not vary by who is asking. Every path that reaches a place
// resolved it through a lookup that carried a subject, so nothing gets here
// without the finding itself having been authorized.
func (s *Store) Applying(ctx context.Context, at Place) (*Decision, error) {
	decision := new(Decision)
	standing, held := finding.InForce()
	// With its argument: what suppresses a finding is the outcome, and a
	// deferral stops standing on a date that is held there too.
	query := s.db.NewSelect().Model(decision).Relation("Claim").
		Where("de.product_id = ?", at.ProductID).
		Where("de.vulnerability_id = ?", at.VulnerabilityID).
		Where("de.place_identity = ?", at.PlaceIdentity).
		// Approved, or proposed and never needing agreement, and not one
		// that was sent back — asked of the one spelling rather than written
		// out here. It was written out here, and the sent-back half was added
		// to this copy alone, so a claim an approver returned went on
		// suppressing its finding everywhere else that asks the same
		// question: the overdue figure, the list, the backlog, the compliance
		// rate, the notice saying a deferral is ending, and the count of what
		// stands on one signature.
		Where(standing, held...)

	// The versions, except where the claim is that the match itself is wrong:
	// that one covers the place at whatever it now holds, because the
	// versions are not what it is about. Grouped, so the two halves are one
	// condition rather than two that a later clause could come between.
	query = query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.WhereOr("claim.outcome = ?", Mismatched).
			WhereGroup(" OR ", func(q *bun.SelectQuery) *bun.SelectQuery {
				q = matchVersion(q, "de.component_upstream_version", at.ComponentUpstream)
				return matchVersion(q, "de.consumer_upstream_version", at.ConsumerUpstream)
			})
	})

	// An agreed claim outranks a waiting one, and a claim that the match is
	// wrong outranks both: a judgment about risk at a place the match does not
	// describe is a judgment about something that is not there. Ordering by
	// identifier alone let a newer unapproved claim shadow an approved one,
	// which is a way for one person to overturn a decision two people made.
	if err := query.OrderExpr(
		"CASE WHEN claim.outcome = ? THEN 0 ELSE 1 END, "+
			"CASE WHEN de.state = ? THEN 0 ELSE 1 END, de.id DESC", Mismatched, Approved).
		Limit(1).Scan(ctx); err != nil {
		// No decision standing is an answer. Anything else is a fault, and
		// reporting it as "nothing stands" would turn a lost race or a lock
		// timeout into a suppressed finding reappearing — or, in an export,
		// into an agreed dismissal silently dropped.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("read what stands here: %w", err)
	}

	// A deferral says "not now, ask again on this date". Once the date has
	// passed it stops standing, and the finding is back in the queue — flagged
	// as something that was deferred rather than as something new, which the
	// kept decision is what says.
	if decision.Claim.Outcome == Deferred && decision.Claim.DeferredUntil != nil {
		if !s.now().Before(*decision.Claim.DeferredUntil) {
			return nil, nil
		}
	}
	return decision, nil
}

// PreviouslyAt returns decisions once made about a place, whatever versions
// they were made against.
//
// The structural half of the key on its own. When a version moves and a
// decision stops applying, somebody has to make the judgment again — and
// making them start from a blank page, having thrown away the reasoning that
// was written the last time, is how a tool teaches people to stop writing
// reasoning at all.
//
// So what comes back is history rather than an answer: the claim that used to
// stand, and the versions it was about. Whether it still holds is the
// question being put, not something this decides.
func (s *Store) PreviouslyAt(ctx context.Context, subject access.Subject, at Place) ([]Decision, error) {
	var previous []Decision
	// With the argument each row applied, which is what is offered back.
	if err := readableBy(s.db.NewSelect().Model(&previous).Relation("Claim"), subject, "de").
		Where("de.product_id = ?", at.ProductID).
		Where("de.vulnerability_id = ?", at.VulnerabilityID).
		Where("de.place_identity = ?", at.PlaceIdentity).
		Order("de.id DESC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what was decided here before: %w", err)
	}
	return previous, nil
}

// matchVersion constrains a query to one stated version, or to none.
//
// A version nobody stated is not the same as a version that is empty, and
// comparing the two as equal would let a decision made about a component with
// no known version stand over one whose version is simply blank. Two absences
// match each other and nothing else.
func matchVersion(query *bun.SelectQuery, column, stated string) *bun.SelectQuery {
	// Read the same way it was written, or the two disagree about what counts
	// as stating nothing.
	trimmed := version(stated)
	if trimmed == "" {
		return query.Where(column + " IS NULL")
	}
	return query.Where(column+" = ?", trimmed)
}

// Revisions returns the reasoning behind a claim, oldest first.
//
// All of it. An approval names one revision, so reading only the current one
// leaves somebody unable to see what was actually agreed to.
func (s *Store) Revisions(ctx context.Context, subject access.Subject, claimID int64) ([]Revision, error) {
	if _, _, err := s.claimRows(ctx, subject, claimID, readable); err != nil {
		return nil, err
	}
	var revisions []Revision
	if err := s.db.NewSelect().Model(&revisions).
		Where("claim_id = ?", claimID).
		Order("ordinal ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the reasoning: %w", err)
	}
	return revisions, nil
}

// Approvals returns who agreed to a claim and to which words, including
// agreements later taken back.
func (s *Store) Approvals(ctx context.Context, subject access.Subject, claimID int64) ([]Approval, error) {
	if _, _, err := s.claimRows(ctx, subject, claimID, readable); err != nil {
		return nil, err
	}
	var approvals []Approval
	if err := s.db.NewSelect().Model(&approvals).
		Where("claim_id = ?", claimID).
		Order("id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who agreed: %w", err)
	}
	return approvals, nil
}

// Age is how long a decision has stood.
//
// Shown wherever a decision appears. It is the compensating control for expiry
// being inert against a producer that patches rather than bumps: an eight-year
// -old judgment should look like one rather than reading the same as
// yesterday's.
func (s *Store) Age(decision *Decision) time.Duration {
	return s.now().Sub(decision.ProposedAt)
}

// Read returns one decision with the reasoning it currently rests on.
//
// Everything a decision endpoint accepts has a matching way to read the
// result. A tool that lets somebody argue, agree and annotate, and then offers
// no way to see what any of it produced, sends every reader to the review
// queue — which by definition no longer holds what was agreed to.
func (s *Store) Read(ctx context.Context, subject access.Subject, decisionID int64) (*Decision, string, error) {
	decision, err := s.reaching(ctx, subject, decisionID, readable, onCases)
	if err != nil {
		return nil, "", err
	}
	reasoning, err := s.currentReasoning(ctx, []Decision{*decision})
	if err != nil {
		return nil, "", err
	}
	return decision, reasoning[decision.ID], nil
}

// ReadClaim reads a claim and the rows it covers, for somebody who may read
// every one of them.
//
// A claim is one argument, so it is refused whole or answered whole: shown
// half, a reader would be told about words whose other half is about a finding
// they may not see.
func (s *Store) ReadClaim(ctx context.Context, subject access.Subject,
	claimID int64) (*Claim, []Decision, error) {

	return s.claimRows(ctx, subject, claimID, readable)
}

// Filter narrows a list of decisions to what somebody is looking for.
//
// An empty field is not a filter. Nobody asking about deferrals wants to be
// told which states exist first.
type Filter struct {
	// ProductIDs, Outcomes and States each narrow to any of what is named.
	// Empty is everything the reader may reach, which is the ordinary case:
	// somebody auditing dismissals is asking across a release rather than
	// about one package.
	//
	// Sets rather than single values, because "dismissed or deferred" and
	// "waiting or sent back" are the questions somebody reading the record
	// actually has, and one value cannot ask either.
	ProductIDs []int64
	Outcomes   []Outcome
	States     []State
	// Expired limits deferrals to those whose date has passed. It is the
	// question a deferral list is usually being asked — what did we put off
	// that has come back — rather than a state anything records.
	Expired bool
	// Stopped is lapsed or expired, as one question: everything that has
	// stopped standing on its own and needs a fresh reason.
	//
	// One filter rather than two lists added together, because a decision can
	// be both — a deferral that ran out on code that then moved — and a sum of
	// two overlapping counts is larger than the thing it labels. The screen
	// that asks this asked both and added them, and said eleven over a list of
	// ten.
	Stopped bool
	// Alone limits to judgments no second person has a standing agreement
	// on.
	//
	// The exception report an auditor asks for, and the one expected to come
	// back empty of dismissals. The population it returns is large and
	// entirely legitimate — an outcome that hides nothing needs no second
	// person, and a short deferral stands on its own — so it is asked together
	// with an outcome. What it is for is showing that no *dismissal* sits in
	// it: not-applicable, wrong match, will-not-fix and already-fixed all
	// require approval, so
	// that query should return nothing, and a row in it is a control that
	// failed.
	//
	// Computed from the record rather than read back from a flag, which is
	// why asking it tests the two-person rule rather than reading an
	// assertion somebody made about it.
	Alone bool
	// InForce limits to judgments that apply now: agreed to, or standing
	// without needing agreement, and still holding the place they were made
	// about.
	//
	// The state filter beside it asks something else. A judgment is approved
	// and still lapses when the code moves out from under it, so a list of
	// approved judgments is a list of what was once agreed rather than of
	// what stands — which is the question asked of the corrections in force,
	// where the whole point is that nothing expires them.
	InForce bool
	// Proposer and Approver limit to one person's part in it, by sign-in
	// identity. Approver matches an agreement that still stands.
	Proposer string
	Approver string
	// Issue and Component name what the judgment was about.
	Issue     string
	Component string
	// TargetID keeps judgments about places one build holds.
	//
	// A decision names no build, deliberately — it is keyed on the
	// product, the issue and the place, so that it carries across the
	// releases that share the code. What a release sign-off asks is the other
	// question: which of these judgments is about something this build
	// actually ships. Reached through the findings at the place, the way the
	// component filter beside it is.
	TargetID int64
}

// List returns decisions matching a filter, newest first, with how many there
// are behind the page.
//
// Newest first because the question this answers is almost always about recent
// judgment: what have we dismissed, what did we defer, what is coming back.
// Oldest-first would put the page nobody wants at the front of every request.
func (s *Store) List(ctx context.Context, subject access.Subject, f Filter,
	limit, offset int) ([]Decision, map[int64]string, int, error) {

	// The outcome and the date are the claim's, so what narrows on them asks
	// the claim. An EXISTS rather than a join, so that counting the page and
	// reading it narrow identically without one of them multiplying rows.
	saying := func(q *bun.SelectQuery, clause string, values ...any) *bun.SelectQuery {
		return q.Where(`EXISTS (SELECT 1 FROM "claim" AS "fc" WHERE fc.id = de.claim_id AND `+
			clause+`)`, values...)
	}
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = readableBy(q, subject, "de")
		if len(f.ProductIDs) > 0 {
			q = q.Where("de.product_id IN (?)", bun.List(f.ProductIDs))
		}
		if len(f.Outcomes) > 0 {
			q = saying(q, "fc.outcome IN (?)", bun.List(f.Outcomes))
		}
		if len(f.States) > 0 {
			q = q.Where("de.state IN (?)", bun.List(f.States))
		}
		if f.Expired {
			q = saying(q, "fc.deferred_until IS NOT NULL AND fc.deferred_until <= ?", s.now())
		}
		if f.Stopped {
			q = q.Where(`(de.state = ? OR EXISTS (SELECT 1 FROM "claim" AS "fc" `+
				`WHERE fc.id = de.claim_id AND fc.deferred_until IS NOT NULL `+
				`AND fc.deferred_until <= ?))`, LapsedState, s.now())
		}
		// The judgment's subject, through the one spelling the record's
		// own page uses. Stated in the filter and applied by only one of the
		// two readers, a caller that set any of the three got the whole
		// unnarrowed list back with no complaint.
		return aboutTheSamePlaces(q, subject, f)
	}

	total, err := narrow(s.db.NewSelect().Model((*Decision)(nil))).Count(ctx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("count what was decided: %w", err)
	}

	var decisions []Decision
	if err := narrow(s.db.NewSelect().Model(&decisions)).Relation("Claim").
		Order("de.id DESC").Limit(limit).Offset(offset).Scan(ctx); err != nil {
		return nil, nil, 0, fmt.Errorf("read what was decided: %w", err)
	}

	// The reasoning comes with the row, for the same reason the review queue
	// carries it: a list where seeing why means opening each entry is a list
	// nobody reads before acting on.
	reasoning, err := s.currentReasoning(ctx, decisions)
	if err != nil {
		return nil, nil, 0, err
	}
	return decisions, reasoning, total, nil
}
