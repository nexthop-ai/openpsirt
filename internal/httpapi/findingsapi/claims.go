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

// decidedAbout gathers what has been decided at a finding's places: what
// stands, what stood before, what was argued about other issues at the same
// places, and what another product decided about this same issue there.
func decidedAbout(ctx context.Context, in core.Deps, subject access.Subject, productID, issueID int64,
	at []finding.Deciding) ([]core.StandingClaimBody, []core.EarlierBody, []core.SimilarBody,
	[]core.ElsewhereBody, error) {

	store := triage.NewStore(in.DB.DB)
	// A standing claim is matched by key — the place and the versions this
	// build ships there — so a decision written against another version of the
	// same place is not reported as standing here. The lapsed and the
	// carryable are asked by place: a lapsed decision no longer matches the
	// versions by definition, and a similar claim is one about other issues at
	// the same place.
	places := make([]string, 0, len(at))
	for _, place := range at {
		places = append(places, place.PlaceIdentity)
	}
	standing, err := store.StandingAt(ctx, subject, productID, issueID, at)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	earlier, err := store.EarlierAt(ctx, subject, productID, issueID, places)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	similar, err := store.SimilarAt(ctx, subject, productID, issueID, places)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// The same issue at the same place in another product. A place identity
	// carries no product, deliberately, so that a place is recognized across
	// variants — and the same key recognizes it across products.
	elsewhere, err := store.DecidedElsewhere(ctx, subject, productID, issueID, places)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	people := []int64{}
	for _, one := range standing {
		people = append(people, one.Claim.ProposedBy, one.ApprovedBy)
	}
	for _, one := range earlier {
		people = append(people, one.Decision.ProposedBy, one.ApprovedBy)
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

	standingOut := make([]core.StandingClaimBody, 0, len(standing))
	for _, one := range standing {
		body := core.StandingClaimBody{
			ClaimID: one.Claim.ID, Kind: core.ClaimKind(one.Claim.Kind), DecisionID: one.Decision.ID,
			State: core.ClaimStateLive(one.State), Outcome: core.Outcome(one.Claim.Outcome),
			Rows: core.RowsStandingBody{
				Proposed: one.Rows.Proposed, SentBack: one.Rows.SentBack, Approved: one.Rows.Approved,
			},
			SentBackBecause: one.SentBackBecause,
			Justification:   core.Justification(core.OrBlank(one.Claim.Justification)),
			FixedVersion:    core.OrBlank(one.Claim.FixedVersion),
			NeedsApproval:   one.Decision.NeedsApproval,
			ProposedBy:      who.Identity(one.Claim.ProposedBy),
			ProposedByName:  who.Label(one.Claim.ProposedBy),
			ProposedAt:      one.Claim.ProposedAt.UTC().Format(time.RFC3339),
			Places:          one.Places, Builds: one.Builds,
			Elsewhere: one.Claim.Elsewhere,
		}
		if body.Builds == nil {
			body.Builds = []string{}
		}
		if one.ApprovedAt != nil {
			body.ApprovedBy, body.ApprovedByName = who.Identity(one.ApprovedBy), who.Label(one.ApprovedBy)
			body.ApprovedAt = one.ApprovedAt.UTC().Format(time.RFC3339)
		}
		if one.SentBackAt != nil {
			body.SentBackAt = one.SentBackAt.UTC().Format(time.RFC3339)
		}
		standingOut = append(standingOut, body)
	}

	earlierOut := make([]core.EarlierBody, 0, len(earlier))
	for _, one := range earlier {
		d := one.Decision
		// The words are the claim's; the landing place is the row's.
		said := d.Claim
		body := core.EarlierBody{
			DecisionID: d.ID, ClaimID: d.ClaimID, Outcome: core.Outcome(said.Outcome),
			Justification: core.Justification(core.OrBlank(said.Justification)),
			ProposedBy:    who.Identity(d.ProposedBy), ProposedByName: who.Label(d.ProposedBy),
			ProposedAt: d.ProposedAt.UTC().Format(time.RFC3339),
			Ended:      core.ClaimStateEnded(d.State),
			About:      core.OrBlank(d.ComponentUpstreamVersion),
			Reasoning:  one.Reasoning,
		}
		if said.FixedVersion != nil {
			body.FixedVersion = *said.FixedVersion
		}
		if said.DeferredUntil != nil {
			body.DeferredUntil = said.DeferredUntil.Format(time.DateOnly)
		}
		if d.EndedAt != nil {
			body.EndedAt = d.EndedAt.UTC().Format(time.RFC3339)
		}
		if one.ApprovedBy != 0 {
			body.ApprovedBy, body.ApprovedByName = who.Identity(one.ApprovedBy), who.Label(one.ApprovedBy)
		}
		earlierOut = append(earlierOut, body)
	}

	similarOut := make([]core.SimilarBody, 0, len(similar))
	for _, one := range similar {
		body := core.SimilarBody{
			ClaimID: one.Claim.ID, DecisionID: one.Decision.ID,
			Justification: core.Justification(core.OrBlank(one.Claim.Justification)),
			Reasoning:     one.Reasoning, Issues: one.Issues,
		}
		if one.ApprovedAt != nil {
			body.ApprovedBy, body.ApprovedByName = who.Identity(one.ApprovedBy), who.Label(one.ApprovedBy)
			body.ApprovedAt = one.ApprovedAt.UTC().Format(time.RFC3339)
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
			Product:       products[one.ProductID],
			ClaimID:       one.Claim.ID,
			DecisionID:    one.Decision.ID,
			Outcome:       core.Outcome(one.Claim.Outcome),
			Justification: core.Justification(core.OrBlank(one.Claim.Justification)),
			Reasoning:     one.Reasoning,
		}
		if one.ApprovedAt != nil {
			body.ApprovedBy, body.ApprovedByName = who.Identity(one.ApprovedBy), who.Label(one.ApprovedBy)
			body.ApprovedAt = one.ApprovedAt.UTC().Format(time.RFC3339)
		}
		elsewhereOut = append(elsewhereOut, body)
	}

	return standingOut, earlierOut, similarOut, elsewhereOut, nil
}
