// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// decidedAbout gathers what has been decided at a finding's occurrences:
// what stands, what stood before, what was argued about other issues at the
// same occurrences, and what another product decided about this same issue there.
func decidedAbout(ctx context.Context, in core.Deps, subject access.Subject, productID, issueID int64,
	at []finding.Deciding) ([]core.StandingDecisionBody, []core.EarlierBody, []core.SimilarBody,
	[]core.ElsewhereBody, error) {

	store := triage.NewStore(in.DB.DB)
	// A standing decision is matched by key — the occurrence and the versions
	// this build ships there — so a decision written against another version
	// of the same occurrence is not reported as standing here. The lapsed and
	// the carryable are asked by occurrence: a lapsed decision no longer
	// matches the versions by definition, and a similar decision is one about
	// other issues at the same occurrence.
	occurrences := make([]string, 0, len(at))
	for _, occurrence := range at {
		occurrences = append(occurrences, occurrence.OccurrenceIdentity)
	}
	standing, err := store.StandingAt(ctx, subject, productID, issueID, at)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	earlier, err := store.EarlierAt(ctx, subject, productID, issueID, occurrences)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	similar, err := store.SimilarAt(ctx, subject, productID, issueID, occurrences)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// The same issue at the same occurrence in another product. An occurrence
	// identity carries no product, deliberately, so that an occurrence is
	// recognized across variants — and the same key recognizes it across products.
	elsewhere, err := store.DecidedElsewhere(ctx, subject, productID, issueID, occurrences)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	people := []int64{}
	for _, one := range standing {
		people = append(people, one.Decision.ProposedBy, one.ApprovedBy)
	}
	for _, one := range earlier {
		people = append(people, one.DecisionOccurrence.ProposedBy, one.ApprovedBy)
	}
	for _, one := range similar {
		people = append(people, one.ApprovedBy)
	}
	for _, one := range elsewhere {
		people = append(people, one.ApprovedBy)
	}
	who, err := core.WhoSigned(ctx, in.DB.DB, people)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	standingOut := make([]core.StandingDecisionBody, 0, len(standing))
	for _, one := range standing {
		body := core.StandingDecisionBody{
			DecisionID: one.Decision.ID, Kind: core.DecisionKind(one.Decision.Kind), DecisionOccurrenceID: one.DecisionOccurrence.ID,
			State: core.DecisionStateLive(one.State), Outcome: core.Outcome(one.Decision.Outcome),
			Rows: core.RowsStandingBody{
				Proposed: one.Rows.Proposed, SentBack: one.Rows.SentBack, Approved: one.Rows.Approved,
			},
			SentBackBecause: one.SentBackBecause,
			Justification:   core.Justification(core.OrBlank(one.Decision.Justification)),
			FixedVersion:    core.OrBlank(one.Decision.FixedVersion),
			NeedsApproval:   one.DecisionOccurrence.NeedsApproval,
			ProposedBy:      who.Identity(one.Decision.ProposedBy),
			ProposedByName:  who.Label(one.Decision.ProposedBy),
			ProposedAt:      core.Stamp(one.Decision.ProposedAt),
			Occurrences:     one.Occurrences, Builds: one.Builds,
			Elsewhere: one.Decision.Elsewhere,
		}
		if body.Builds == nil {
			body.Builds = []string{}
		}
		if one.ApprovedAt != nil {
			body.ApprovedBy, body.ApprovedByName = who.Identity(one.ApprovedBy), who.Label(one.ApprovedBy)
			body.ApprovedAt = core.StampAt(one.ApprovedAt)
		}
		body.SentBackAt = core.StampAt(one.SentBackAt)
		standingOut = append(standingOut, body)
	}

	earlierOut := make([]core.EarlierBody, 0, len(earlier))
	for _, one := range earlier {
		d := one.DecisionOccurrence
		// The words are the decision's; the landing place is the occurrence's.
		said := d.Decision
		body := core.EarlierBody{
			DecisionOccurrenceID: d.ID, DecisionID: d.DecisionID, Outcome: core.Outcome(said.Outcome),
			Justification: core.Justification(core.OrBlank(said.Justification)),
			ProposedBy:    who.Identity(d.ProposedBy), ProposedByName: who.Label(d.ProposedBy),
			ProposedAt: core.Stamp(d.ProposedAt),
			Ended:      core.DecisionStateEnded(d.State),
			About:      core.OrBlank(d.ComponentUpstreamVersion),
			Reasoning:  one.Reasoning,
		}
		if said.FixedVersion != nil {
			body.FixedVersion = *said.FixedVersion
		}
		if said.DeferredUntil != nil {
			body.DeferredUntil = said.DeferredUntil.UTC().Format(time.DateOnly)
		}
		body.EndedAt = core.StampAt(d.EndedAt)
		if one.ApprovedBy != 0 {
			body.ApprovedBy, body.ApprovedByName = who.Identity(one.ApprovedBy), who.Label(one.ApprovedBy)
		}
		earlierOut = append(earlierOut, body)
	}

	similarOut := make([]core.SimilarBody, 0, len(similar))
	for _, one := range similar {
		body := core.SimilarBody{
			DecisionID: one.Decision.ID, DecisionOccurrenceID: one.DecisionOccurrence.ID,
			Justification: core.Justification(core.OrBlank(one.Decision.Justification)),
			Reasoning:     one.Reasoning, Issues: one.Issues,
		}
		if one.ApprovedAt != nil {
			body.ApprovedBy, body.ApprovedByName = who.Identity(one.ApprovedBy), who.Label(one.ApprovedBy)
			body.ApprovedAt = core.StampAt(one.ApprovedAt)
		}
		similarOut = append(similarOut, body)
	}
	products, err := core.ProductsDecidedIn(ctx, in, elsewhere)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	elsewhereOut := make([]core.ElsewhereBody, 0, len(elsewhere))
	for _, one := range elsewhere {
		body := core.ElsewhereBody{
			Product:              products[one.ProductID],
			DecisionID:           one.Decision.ID,
			DecisionOccurrenceID: one.DecisionOccurrence.ID,
			Outcome:              core.Outcome(one.Decision.Outcome),
			Justification:        core.Justification(core.OrBlank(one.Decision.Justification)),
			Reasoning:            one.Reasoning,
		}
		if one.ApprovedAt != nil {
			body.ApprovedBy, body.ApprovedByName = who.Identity(one.ApprovedBy), who.Label(one.ApprovedBy)
			body.ApprovedAt = core.StampAt(one.ApprovedAt)
		}
		elsewhereOut = append(elsewhereOut, body)
	}

	return standingOut, earlierOut, similarOut, elsewhereOut, nil
}
