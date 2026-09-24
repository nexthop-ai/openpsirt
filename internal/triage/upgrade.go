// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Upgrade is a promise to move a component, in the builds named, by a date.
type Upgrade struct {
	ProductID int64
	// Component is what moves. Coverage is the component rather than a version
	// pair: an upgrade is a claim that moving the package answers what is open
	// on it, and the next scan says which of that was true.
	Component string
	// Version is the source version the promise is about, where one build
	// ships the component at two. Empty where each build ships one.
	Version string
	// To is the version it moves to, and By when the work will be done.
	To string
	By time.Time
	// Builds are the releases this is promised for. The same component can be
	// promised a different version in another build, which is the ordinary
	// case rather than a conflict: a stream on a maintained older line and a
	// stream that has moved on are different work.
	Builds    []int64
	Reasoning string
	// HoldBy is the party carrying the work, where somebody said. A person
	// or a team, in the column that already holds one — a team is a
	// perfectly good holder of an upgrade, and often the right one,
	// because moving a package is a piece of work a queue tracks rather
	// than a judgment one person makes.
	//
	// Recorded in the same transaction as the promise, so a promise nobody
	// is carrying and a holder with no promise are both impossible.
	HoldBy *int64
}

// PlanUpgrade records moving a component as the answer to what is open on it.
//
// One act, one claim, one decision per issue — the same shape a bulk
// judgment takes, because a bump answers many issues at once and
// answering them one at a time is what the grouping exists to avoid.
//
// Gated on where the date lands rather than on the outcome alone. A
// commitment at or before the earliest deadline among what it covers hides
// nothing the policy did not already allow, so it stands on its own; past that
// deadline it defers the worst thing it covers and a second person agrees.
// Worked out here rather than by the caller, because the deadline is a fact
// about the set this resolves and the caller does not have it.
//
// It takes no bound. A bulk judgment takes one and this does not, and the
// difference is reversibility rather than size: nothing re-checks a dismissal,
// so one sentence answering a thousand findings has to stay a size a reviewer
// can follow, while the next scan re-checks every row a promise names.
func (s *Store) PlanUpgrade(ctx context.Context, subject access.Subject,
	up Upgrade) (Declared, error) {

	if strings.TrimSpace(up.Reasoning) == "" {
		return Declared{}, fmt.Errorf("say why this is being upgraded")
	}
	if strings.TrimSpace(up.To) == "" {
		return Declared{}, fmt.Errorf("say which version this moves to")
	}
	if up.By.IsZero() {
		return Declared{}, fmt.Errorf("say when this will be done")
	}
	// Asked of the one predicate rather than written out: the same question
	// every other write here asks, and a second spelling of it is a second
	// rule to keep in step.
	if !subject.TriagesIn(up.ProductID) {
		return Declared{}, access.Denied(
			fmt.Sprintf("decide what is fixed in product %d", up.ProductID))
	}

	db, err := s.pool()
	if err != nil {
		return Declared{}, err
	}
	findings := finding.NewStore(db)

	var out Declared
	err = database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		out = Declared{}
		within := &Store{db: tx, now: s.now}

		wanted, err := findings.BuildsForWithin(ctx, tx, up.ProductID, up.Builds)
		if err != nil {
			return err
		}
		if len(wanted) == 0 {
			return fmt.Errorf("name at least one release this is promised for")
		}
		retired, err := findings.RetiredWithin(ctx, tx, up.Builds)
		if err != nil {
			return err
		}
		// Only the builds this is promised for. An upgrade of one stream says
		// nothing about another, which is the whole reason the target is per
		// build.
		reaching, err := findings.PlacesOnComponentWithin(ctx, tx, subject, up.ProductID,
			wanted, up.Component, up.Version)
		if err != nil {
			return err
		}
		if len(reaching) == 0 {
			return fmt.Errorf("%w: nothing is open against that component in those releases",
				ErrNothingOpen)
		}

		// binding is what the promise is measured against: the
		// earliest deadline among what it covers. One act covering a
		// critical and a medium is gated by the critical, however many
		// mediums are in it.
		var binding *time.Time
		for _, at := range reaching {
			for _, place := range at.Places {
				if place.DueAt == nil {
					continue
				}
				if binding == nil || place.DueAt.Before(*binding) {
					binding = place.DueAt
				}
			}
		}
		gated := commitmentGated(&up.By, binding)

		type standsAt struct {
			vulnerability                        int64
			place, componentUpstream, consumerUp string
		}
		proposals := make([]Proposal, 0, len(reaching))
		written := make(map[standsAt]int, len(reaching))
		issues := map[int64]bool{}
		components := map[int64]bool{}
		for _, at := range reaching {
			issues[at.VulnerabilityID] = true
			components[at.ComponentID] = true
			for _, place := range at.Places {
				key := standsAt{place.VulnerabilityID, place.PlaceIdentity,
					place.ComponentUpstream, place.ConsumerUpstream}
				if already, seen := written[key]; seen {
					// The stricter visibility of the two, for the reason a
					// bundle takes it: one place decided once.
					if place.Visibility == access.Private {
						proposals[already].Place.Visibility = access.Private
					}
					continue
				}
				written[key] = len(proposals)
				proposals = append(proposals, Proposal{
					Place: Place{
						ProductID: place.ProductID, VulnerabilityID: place.VulnerabilityID,
						PlaceIdentity: place.PlaceIdentity, Visibility: place.Visibility,
						ComponentUpstream: place.ComponentUpstream,
						ConsumerUpstream:  place.ConsumerUpstream,
						OnTag:             place.OnTag,
					},
					Outcome:       UpgradeNeeded,
					UpgradeTo:     up.To,
					CommittedTo:   &up.By,
					Binding:       binding,
					Reasoning:     up.Reasoning,
					By:            subject.ID,
					SeverityCenti: place.SeverityCenti,
					NeedsApproval: gated,
				})
			}
		}
		// Every check a bulk judgment makes except the bound. A promise to
		// upgrade is not bounded: the cap is there so that one sentence
		// answering a thousand findings stays a size a reviewer can follow,
		// and nothing re-checks a dismissal afterwards — while the next scan
		// re-checks every row a promise names. Narrowing one would make the
		// record false, because the bump closes what it closes.
		//
		// One kernel bump in a real image reaches 4,485 findings across 44,016
		// places, and a cumulative bundle reaches 243,945. Bounded at the
		// shipped two thousand, the highest-value action in the data was
		// refused by a factor of twenty-two, and the only escape offered was
		// raising a setting that guards the dismissal path this one has
		// nothing to do with.
		//
		// The cost of committing one of that size is measured rather than
		// assumed: 8.3 s on SQLite, 8.4 s on MariaDB, 10.9 s on MySQL and
		// 23.9 s on PostgreSQL, under "make measure".
		if err := permitted(subject, proposals, s.now()); err != nil {
			return err
		}
		out.Issues, out.Components = len(issues), len(components)
		out.Waiting = gated

		// One act, one argument: every proposal here promises the same
		// version by the same date, and what varies per place is the versions
		// it was made against and whether a second person has to agree.
		claim, err := within.newClaim(ctx, FindingClaim, subject.ID, nil, "", proposals[0])
		if err != nil {
			return err
		}
		out.ClaimID = claim.ID
		made, err := within.proposeAll(ctx, claim, proposals)
		if err != nil {
			return err
		}
		out.Decisions = len(made)
		// The commitment per build, which is what the pending-upgrades screen
		// reads. One row per build and fold rather than one per issue: a bump
		// moves the source package, so what it covers is a join and everything
		// open on the fold follows it — including an issue published tonight.
		work := make([][2]int64, 0, len(reaching))
		committed := map[int64]bool{}
		for _, at := range reaching {
			work = append(work, [2]int64{at.VulnerabilityID, at.ComponentID})
			if committed[at.ComponentID] {
				continue
			}
			committed[at.ComponentID] = true
			n, err := findings.CommitWithin(ctx, tx, subject, up.ProductID,
				at.ComponentID, up.To, &up.By, &claim.ID, wanted, retired)
			if err != nil {
				return err
			}
			out.Targets += n
		}
		// The person carrying it, where somebody said. Part of the same act
		// rather than a second one: a bump nobody is holding is a promise with
		// no owner, and the screen that records it is the screen that knows
		// who the owner is.
		if up.HoldBy != nil {
			held, err := findings.HandOverWithin(ctx, tx, subject, up.ProductID, work, up.HoldBy)
			if err != nil {
				return err
			}
			out.Held = int(held)
		}
		return nil
	})
	if err != nil {
		return Declared{}, err
	}
	return out, nil
}

// Repromise changes what a release is moving to, or by when.
//
// Editing a commitment is editing what somebody agreed to. An approver
// agreed to "8.5.0 by 8 October"; a coordinator quietly rewriting either half
// would leave the agreement standing over a promise nobody read, which is the
// failure REQ-28 exists to prevent — so this goes through the same act revising
// the words does: every agreement on the claim is withdrawn and every row of it
// returns to the queue.
//
// The reasoning is required, and it is the history. Saying why a date moved
// is what a second person has to read, and the revisions are where "what we
// said in October" survives being changed in November. A promise moved with no
// sentence attached is a promise nobody can audit.
func (s *Store) Repromise(ctx context.Context, subject access.Subject, claimID int64,
	to string, by time.Time, reasoning string) error {

	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("say which version this is moving to")
	}
	if strings.TrimSpace(reasoning) == "" {
		return fmt.Errorf("say why the promise is changing: a date moved with no reason " +
			"is one nobody can agree to again")
	}
	db, err := s.pool()
	if err != nil {
		return err
	}
	findings := finding.NewStore(db)
	return database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		within := &Store{db: tx, now: s.now}
		claim, rows, err := within.claimRows(ctx, subject, claimID, mayDecide)
		if err != nil {
			return err
		}
		if claim.Outcome != UpgradeNeeded {
			return fmt.Errorf("that claim is %s, and only a promised upgrade has a version to move",
				claim.Outcome)
		}
		for _, row := range rows {
			if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
				return ErrNotTheirs
			}
		}
		moving := strings.TrimSpace(to)
		when := by.UTC()
		if !when.After(s.now()) {
			return fmt.Errorf("a promise lands on a date still to come: %s has passed",
				when.Format(time.DateOnly))
		}

		// The gate again, over what the claim covers now. Moving the date is
		// moving the thing the gate is about, so a promise first made inside
		// the deadline and then pushed years out would otherwise stay
		// recorded as needing nobody — in force, suppressing everything it
		// covers, and out of the review queue, which is a seven-year deferral
		// on one signature.
		//
		// Resolved here rather than remembered: the deadline moves when the
		// policy or the rating moves, and this is inside the transaction that
		// writes so a retry cannot gate against a database that has gone.
		gated, err := within.regate(ctx, tx, findings, subject, claimID, rows, when)
		if err != nil {
			return err
		}
		if _, err := tx.NewUpdate().Model((*Claim)(nil)).
			Set("upgrade_to = ?", moving).
			Set("committed_to = ?", when).
			Where("id = ?", claimID).Exec(ctx); err != nil {
			return fmt.Errorf("change what was promised: %w", err)
		}
		// The commitments this claim wrote, moved with it. One row per build
		// and fold, so changing the version a release is moving to is one
		// update however many findings it covers.
		if _, err := tx.NewUpdate().Table("upgrade").
			Set("to_version = ?", moving).
			Set("committed_to = ?", when).
			Where("claim_id = ?", claimID).Exec(ctx); err != nil {
			return fmt.Errorf("change what the releases are waiting on: %w", err)
		}
		// Written with the revision rather than after it, because the two are
		// one act: a row back in the queue that still says it needs nobody is
		// a row the queue does not list.
		if _, err := tx.NewUpdate().Model((*Decision)(nil)).
			Set("needs_approval = ?", gated).
			Where("claim_id = ?", claimID).Exec(ctx); err != nil {
			return fmt.Errorf("record whether the changed promise needs agreement: %w", err)
		}
		// Last, because it is what returns the rows to the queue: an approver
		// meeting it again is reading a promise that has changed.
		if _, err := within.revise(ctx, subject, claimID, reasoning); err != nil {
			return err
		}
		return nil
	})
}

// regate works out whether a changed promise needs a second person, from what
// the claim covers rather than from what it covered when it was made.
//
// The builds come from the commitments the claim wrote, which are what says
// where the promise applies, and the places from the claim's own rows. The
// deadline is then the earliest among the findings still open at those places
// in those builds.
func (s *Store) regate(ctx context.Context, tx bun.Tx, findings *finding.Store,
	subject access.Subject, claimID int64, rows []Decision, by time.Time) (bool, error) {

	if len(rows) == 0 {
		return true, nil
	}
	var targets []int64
	if err := tx.NewSelect().Table("upgrade").
		ColumnExpr("DISTINCT target_id").
		Where("claim_id = ?", claimID).Scan(ctx, &targets); err != nil {
		return false, fmt.Errorf("read which releases this was promised for: %w", err)
	}
	places := make([]finding.At, 0, len(rows))
	for _, row := range rows {
		places = append(places, finding.At{
			VulnerabilityID: row.VulnerabilityID, PlaceIdentity: row.PlaceIdentity,
		})
	}
	binding, err := findings.DeadlineAt(ctx, tx, subject, rows[0].ProductID, targets, places)
	if err != nil {
		return false, err
	}
	return commitmentGated(&by, binding), nil
}
