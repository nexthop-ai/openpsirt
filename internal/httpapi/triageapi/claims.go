// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// ClaimApprovalBody is the body of an approval.
type ClaimApprovalBody struct {
	// Bounded to what the column holds. A name is compared for equality and
	// never read back on its own, so it shares the width of a hash.
	Batch string `json:"batch,omitempty" maxLength:"64" doc:"Name a batch to agree to several claims under one name, so they can be undone together. At most 64 characters"`
	// Except sets rows aside. The remainder is approved as one claim; these go
	// back to the proposer as a claim of their own, with the reason.
	Except  []int64 `json:"except,omitempty" maxItems:"2000" doc:"Decisions in this claim to set aside rather than approve. They return to the proposer as a claim of their own, carrying the reason given in because"`
	Because string  `json:"because,omitempty" doc:"The reason the rows in except are set aside, in markdown. Required when any are"`
}

// ClaimApprovedBody is the record of an approval.
type ClaimApprovedBody struct {
	Approved      int   `json:"approved" doc:"The number of decisions agreed to"`
	ReturnedClaim int64 `json:"returned_claim,omitempty" doc:"The claim the rows set aside went into, where any were"`
}

func registerClaims(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "approve-claim", Method: http.MethodPost, Path: "/v1/claims/{id}/approval",
		Summary: "Approve a claim",
		Description: "Approves every waiting decision in a claim as one action, under the same " +
			"rules each decision is approved under: not by the person who proposed it, and " +
			"against the revision of the reasoning that stands now.\n\n" +
			"Name decisions in `except` to set them aside. The rest is approved; those are " +
			"moved into a claim of their own, marked sent back, and `because` is recorded on " +
			"each as a comment — the same way sending back records a reason. The response " +
			"names that claim.\n\n" +
			"Pass `batch` to approve several claims under one name, undone together with " +
			"`DELETE /v1/approval-batches/{batch}`.\n\n" +
			"Returns 404 for a claim you may not act on every row of, and 409 if you proposed it.",
		Tags: []string{"Triage"},
	}, core.PerProduct, "The proposer may not approve their own.", core.ApproveRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body ClaimApprovalBody
	}) (*struct{ Body ClaimApprovedBody }, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		done, err := store.ApproveClaim(ctx, subject, input.ID, input.Body.Batch,
			input.Body.Except, input.Body.Because)
		switch {
		case errors.Is(err, triage.ErrSamePerson):
			return nil, huma.Error409Conflict(
				"the person who proposed a claim may not be the one who agrees to it")
		case errors.Is(err, triage.ErrNotTheirs):
			return nil, noSuchClaim()
		case err != nil:
			return nil, core.RefusedDecision(in.Logger, err)
		}

		out := &struct{ Body ClaimApprovedBody }{}
		out.Body.Approved = done.Approved
		if done.Returned != nil {
			out.Body.ReturnedClaim = done.Returned.ID
			// The rows go back to whoever proposed them, and
			// they should hear rather than find out. Logged on
			// failure: the rows are returned either way.
			core.Tell(ctx, in, "could not say that rows were set aside", notify.Telling{
				PersonID: done.Returned.ProposedBy, Kind: notify.SentBack,
				Body: "Part of a claim of yours was set aside: " + input.Body.Because,
				Link: weblink.ReviewQueue(),
				// A claim covers many findings and this path
				// holds the claim rather than any of them, so
				// the disclosure of any one of them cannot be
				// answered from here. Treated as though one
				// is undisclosed: the direction to be wrong in is a link
				// somebody has to follow, not an approver's
				// words about an embargo landing in a mail
				// server.
				Private: true,
				// The product the returned rows are in, which
				// is what a later read narrows by.
				ProductID: &done.ReturnedIn,
			}, "claim", input.ID)
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "send-claim-back", Method: http.MethodPost, Path: "/v1/claims/{id}/send-back",
		Summary: "Send a claim back for more",
		Description: "Asks the author for more before agreeing to any of a claim. Every waiting " +
			"decision in it leaves the review queue together and comes back when the author " +
			"revises.\n\n" +
			"`because` is required and is recorded as a comment on each decision. Needs no " +
			"approval of its own. You cannot send back a claim whose words are your own.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "The proposer may not approve their own.", core.ApproveRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Because string `json:"because" minLength:"1" doc:"The change being asked for, in markdown"`
		}
	}) (*struct{}, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		back, err := store.SendBackClaim(ctx, subject, input.ID, input.Body.Because)
		if err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchClaim()
			}
			return nil, core.RefusedDecision(in.Logger, err)
		}
		// Everybody whose words went back is told, and sent to the finding
		// the claim is about: that is where the words are revised, where the
		// review queue lists what waits on an approver and leaves out what
		// waits on its author. The decision itself stands in where no open
		// finding the sender may read describes it any more.
		link := weblink.Decision(back.Decision.ID)
		if described, err := store.Describe(ctx, subject, []triage.Decision{back.Decision}); err == nil {
			if d, ok := described[back.Decision.ID]; ok {
				link = weblink.Finding(d.Product, d.Stream, d.Variant,
					d.Issue.Identifier, d.Component, d.Version)
			}
		} else if err != nil {
			in.Log().Error("could not say which finding a sent-back claim is about",
				"error", err, "claim", input.ID)
		}
		{
			author := back.Author
			core.Tell(ctx, in, "could not say that a claim was sent back", notify.Telling{
				PersonID: author, Kind: notify.SentBack,
				Body: "A claim of yours was sent back: " + input.Body.Because,
				Link: link,
				// The words an approver wrote are about the
				// findings, so they are as private as the most
				// careful of them. Read off the claim rather
				// than off its representative row: that row is
				// chosen by identifier and a claim's rows need
				// not agree.
				Private: back.Undisclosed,
				// Off the representative row, which is a row of
				// this claim and so names its product and its
				// issue.
				ProductID:       &back.Decision.ProductID,
				VulnerabilityID: &back.Decision.VulnerabilityID,
			}, "claim", input.ID, "person", author)
		}
		return &struct{}{}, nil
	})
}

// registerClaimLink is where a claim's work is happening.
func registerClaimLink(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "point-claim-elsewhere", Method: http.MethodPut,
		Path:    "/v1/claims/{id}/elsewhere",
		Summary: "Record where this claim's work is happening",
		Description: "Stores a link to a ticket, a thread or a change — and sends nothing to " +
			"it. A stored link has no egress at all, which is what makes it available to a " +
			"deployment that has not decided to let anything out; the half that *sends* is a " +
			"separate thing a deployment configures.\n\n" +
			"Anybody who may argue about the claim may set it: a link is a note about where " +
			"the conversation is rather than a judgment, and needing a second person for it " +
			"would leave it unset.\n\n" +
			"Sent empty it is cleared. A stale link is worse than none — it sends somebody to " +
			"a ticket that closed for a different reason.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Elsewhere string `json:"elsewhere" maxLength:"1000" doc:"The place the work is happening. Empty clears it"`
		}
	}) (*struct{}, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		if err := store.PointAt(ctx, subject, input.ID, input.Body.Elsewhere); err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchClaim()
			}
			return nil, core.RefusedDecision(in.Logger, err)
		}
		return &struct{}{}, nil
	})
}

// noSuchClaim is the one answer for a claim that is not there or not yours.
func noSuchClaim() error {
	return huma.Error404NotFound("no such claim")
}

// ReaffirmedBody is the record of one bulk re-affirmation.
type ReaffirmedBody struct {
	PreviousClaimID int64   `json:"previous_claim_id" doc:"The claim that lapsed"`
	ClaimID         int64   `json:"claim_id" doc:"The claim this action made, which is what a second person agrees to where one is needed"`
	Decisions       []int64 `json:"decisions"`
	Places          int     `json:"places" doc:"The number of distinct places it covers. A place at two versions in two builds is two decisions, because the versions are what a decision expires on"`
	Waiting         bool    `json:"waiting" doc:"Whether a second person has to agree"`
}

// registerReaffirmClaim re-makes everything one action claimed.
func registerReaffirmClaim(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "reaffirm-claim", Method: http.MethodPost,
		Path:    "/v1/claims/{id}/reaffirmation",
		Summary: "Re-affirm everything one action claimed",
		Description: "Re-makes every row of this claim that stopped applying because an " +
			"upstream version moved, at the versions each place has now, as one act with one " +
			"reasoning.\n\n" +
			"Deciding is bulk-capable and re-deciding was not. A team answering one kernel " +
			"issue writes a decision at each of its places in one action; when the kernel " +
			"moves, those lapse, and restoring them was one request each with a separately " +
			"typed justification.\n\n" +
			"Only the person who made the original may do this. It normally needs no second " +
			"approver, for the reason the single form does not: two people already agreed, and " +
			"a version upgrade is a prompt to re-check rather than a new claim.\n\n" +
			"One act, one approval. Where any row would need approval again — nothing was " +
			"ever agreed to, or the issue is rated a band worse since it was agreed to and " +
			"the claim is one a severity bears on — the whole act does. An approver works at the unit " +
			"the proposer acted at. A severity bears on every claim except `already-fixed`, " +
			"and `not-applicable` because the component or the vulnerable code is not present " +
			"or not in the execute path.\n\n" +
			"Bounded unless it is a promise to upgrade. The issues it covers count against " +
			"`triage.agreed-issues` where nothing goes back to an approver, and against " +
			"`triage.review-issues` where anything does; the findings it writes count against " +
			"`triage.write-ceiling`.\n\n" +
			"A place that is open nowhere any more is not re-made, which is a finding that " +
			"closed rather than a fault. `reasoning` is required.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, core.AnyPerson, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Reasoning string `json:"reasoning" minLength:"1" doc:"The reason every one of them still holds, in markdown"`
		}
	}) (*struct{ Body ReaffirmedBody }, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		// Held to the deployment's bounds, which the store reads inside the
		// write. Only a promise goes through unbounded, and which of the two
		// this is comes from the claim being re-made rather than from the
		// request.
		made, err := store.ReaffirmClaim(ctx, subject, triage.ReaffirmingClaim{
			PreviousClaimID: input.ID,
			Reasoning:       input.Body.Reasoning,
			By:              subject.ID,
		})
		if err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchClaim()
			}
			return nil, core.RefusedDecision(in.Logger, err)
		}
		return &struct{ Body ReaffirmedBody }{Body: reaffirmedBody(made)}, nil
	})
}

func claimBody(c triage.Claim, proposedBy, proposedByName string) ClaimBody {
	body := ClaimBody{
		ID: c.ID, Kind: core.ClaimKind(c.Kind), ProposedBy: proposedBy, ProposedByName: proposedByName,
		ProposedAt: c.ProposedAt.UTC().Format(time.RFC3339),
		Elsewhere:  c.Elsewhere,
	}
	if c.DerivedFrom != nil {
		body.DerivedFrom = *c.DerivedFrom
	}
	if c.SelectedBy != nil {
		body.SelectedBy = *c.SelectedBy
	}
	if c.SelectedMatched != nil && c.SelectedNamed != nil {
		body.Selection = &SelectionBody{
			Matched: *c.SelectedMatched, Named: *c.SelectedNamed,
		}
		if c.SelectedWhere != nil {
			body.Selection.Contains = *c.SelectedWhere
		}
	}
	return body
}

func outliersBody(o triage.Outliers) *OutliersBody {
	body := &OutliersBody{
		ExploitedHere: o.ExploitedHere,
		Exploited:     o.Exploited, Severe: o.Severe, Fixable: o.Fixable, Unmatched: o.Unmatched,
		Rows: make([]OutlierBody, 0, len(o.Rows)),
	}
	for _, row := range o.Rows {
		body.Rows = append(body.Rows, OutlierBody{
			DecisionID: row.DecisionID, DecisionIDs: row.DecisionIDs,
			Vulnerability: row.Vulnerability, Severity: row.Severity,
			ExploitedHere: row.ExploitedHere, Exploited: row.Exploited, FixedIn: row.FixedIn,
			Description: row.Description, Why: row.Why,
		})
	}
	return body
}
