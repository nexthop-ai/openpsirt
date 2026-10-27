// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// DecisionApprovalBody is the body of an approval.
type DecisionApprovalBody struct {
	// Bounded to what the column holds. A name is compared for equality and
	// never read back on its own, so it shares the width of a hash.
	Batch string `json:"batch,omitempty" maxLength:"64" doc:"Name a batch to agree to several decisions under one name, so they can be undone together. At most 64 characters"`
	// Except sets rows aside. The remainder is approved as one decision; these go
	// back to the proposer as a decision of their own, with the reason.
	Except  []int64 `json:"except,omitempty" maxItems:"2000" doc:"Occurrences of this decision to set aside rather than approve, by decision occurrence identifier. They return to the proposer as a decision of their own, carrying the reason given in because"`
	Because string  `json:"because,omitempty" doc:"The reason the occurrences in except are set aside, in markdown. Required when any are"`
}

// DecisionApprovedBody is the record of an approval.
type DecisionApprovedBody struct {
	Approved         int   `json:"approved" doc:"The number of occurrences agreed to"`
	ReturnedDecision int64 `json:"returned_decision,omitempty" doc:"The decision the occurrences set aside went into, where any were"`
}

func registerDecisions(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "approve-decision", Method: http.MethodPost, Path: "/v1/decisions/{id}/approval",
		Summary: "Approve a decision",
		Description: "Approves every occurrence of a decision still waiting, as one action, under the same " +
			"rules each occurrence is approved under: not by the person who proposed it, and " +
			"against the revision of the reasoning that stands now.\n\n" +
			"Name occurrences in `except` to set them aside. The rest is approved; those are " +
			"moved into a decision of their own, marked sent back, and `because` is recorded on " +
			"each as a comment — the same way sending back records a reason. The response " +
			"names that decision.\n\n" +
			"Pass `batch` to approve several decisions under one name, undone together with " +
			"`DELETE /v1/approval-batches/{batch}`.\n\n" +
			"Returns 404 for a decision you may not act on every occurrence of, and 409 if you proposed it.",
		Tags: []string{"Triage"},
	}, core.PerProduct, "The proposer may not approve their own.", core.ApproveRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body DecisionApprovalBody
	}) (*struct{ Body DecisionApprovedBody }, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		done, err := store.ApproveDecision(ctx, subject, input.ID, input.Body.Batch,
			input.Body.Except, input.Body.Because)
		switch {
		case errors.Is(err, triage.ErrSamePerson):
			return nil, huma.Error409Conflict(
				"somebody who proposed any of a decision or wrote any of its reasoning may not agree to it")
		case errors.Is(err, triage.ErrNotTheirs):
			return nil, noSuchDecision()
		case err != nil:
			return nil, core.RefusedDecision(in.Logger, err)
		}

		out := &struct{ Body DecisionApprovedBody }{}
		out.Body.Approved = done.Approved
		if done.Returned != nil {
			out.Body.ReturnedDecision = done.Returned.ID
			// The rows go back to whoever proposed them, and
			// they should hear rather than find out. Logged on
			// failure: the rows are returned either way.
			core.Tell(ctx, in, "could not say that rows were set aside", notify.Telling{
				PersonID: done.Returned.ProposedBy, Kind: notify.SentBack,
				Body: "Part of a decision of yours was set aside: " + input.Body.Because,
				Link: weblink.ReviewQueue(),
				// A decision covers many findings and this path
				// holds the decision rather than any of them, so
				// the disclosure of any one of them cannot be
				// answered from here. Treated as though one
				// is undisclosed: the direction to be wrong in is a link
				// somebody has to follow, not an approver's
				// words about an embargo landing in a mail
				// server.
				Private: true,
				// Withheld as internal where any row set aside is
				// internal work, which a reader of undisclosed work
				// alone does not read.
				Internal: done.ReturnedInternal,
				// The product the returned rows are in, which
				// is what a later read narrows by.
				ProductID: &done.ReturnedIn,
			}, "decision", input.ID)
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "send-decision-back", Method: http.MethodPost, Path: "/v1/decisions/{id}/send-back",
		Summary: "Send a decision back for more",
		Description: "Asks the author for more before agreeing to any of a decision. Every waiting " +
			"occurrence of it leaves the review queue at once and comes back when the author " +
			"revises.\n\n" +
			"`because` is required and is recorded as a comment on the decision. Needs no " +
			"approval of its own. You cannot send back a decision whose words are your own.",
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
		back, err := store.SendBackDecision(ctx, subject, input.ID, input.Body.Because)
		if err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchDecision()
			}
			return nil, core.RefusedDecision(in.Logger, err)
		}
		// Everybody whose words went back is told, and sent to the finding
		// the decision is about: that is where the words are revised, where the
		// review queue lists what waits on an approver and leaves out what
		// waits on its author. The decision itself stands in where no open
		// finding the sender may read describes it any more.
		link := weblink.DecisionOccurrence(back.DecisionOccurrence.ID)
		if described, err := store.Describe(ctx, subject, []triage.DecisionOccurrence{back.DecisionOccurrence}); err == nil {
			if d, ok := described[back.DecisionOccurrence.ID]; ok {
				link = weblink.Finding(d.Product, d.Stream, d.Variant,
					d.Issue.Identifier, d.Component, d.Version)
				// A rule names no finding page; its lead is addressed by
				// its occurrence.
				if d.Issue.Kind == kind.Rule {
					link = weblink.Lead(d.Product, d.Stream, d.Variant, back.DecisionOccurrence.OccurrenceIdentity)
				}
			}
		} else if err != nil {
			in.Log().Error("could not say which finding a sent-back decision is about",
				"error", err, "decision", input.ID)
		}
		{
			author := back.Author
			core.Tell(ctx, in, "could not say that a decision was sent back", notify.Telling{
				PersonID: author, Kind: notify.SentBack,
				Body: "A decision of yours was sent back: " + input.Body.Because,
				Link: link,
				// The words an approver wrote are about the
				// findings, so they are as private as the most
				// careful of them. Read off the decision rather
				// than off its representative row: that row is
				// chosen by identifier and a decision's rows need
				// not agree.
				Private:  back.Undisclosed,
				Internal: back.Internal,
				// Off the representative row, which is a row of
				// this decision and so names its product and its
				// issue.
				ProductID:       &back.DecisionOccurrence.ProductID,
				VulnerabilityID: &back.DecisionOccurrence.VulnerabilityID,
			}, "decision", input.ID, "person", author)
		}
		return &struct{}{}, nil
	})
}

// registerDecisionLink is where a decision's work is happening.
func registerDecisionLink(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "point-decision-elsewhere", Method: http.MethodPut,
		Path:    "/v1/decisions/{id}/elsewhere",
		Summary: "Record where this decision's work is happening",
		Description: "Stores a link to a ticket, a thread or a change — and sends nothing to " +
			"it. A stored link has no egress at all, which is what makes it available to a " +
			"deployment that has not decided to let anything out; the half that *sends* is a " +
			"separate thing a deployment configures.\n\n" +
			"Anybody who may argue about the decision may set it: a link is a note about where " +
			"the conversation is rather than a decision, and needing a second person for it " +
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
				return nil, noSuchDecision()
			}
			return nil, core.RefusedDecision(in.Logger, err)
		}
		return &struct{}{}, nil
	})
}

// noSuchDecision is the one answer for a decision that is not there or not yours.
func noSuchDecision() error {
	return huma.Error404NotFound("no such decision")
}

// ReaffirmedBody is the record of one bulk re-affirmation.
type ReaffirmedBody struct {
	PreviousDecisionID  int64   `json:"previous_decision_id" doc:"The decision that lapsed"`
	DecisionID          int64   `json:"decision_id" doc:"The decision this action made, which is what a second person agrees to where one is needed"`
	DecisionOccurrences []int64 `json:"decision_occurrences"`
	Occurrences         int     `json:"occurrences" doc:"The number of distinct occurrences it covers. An occurrence at two versions in two builds is two decision occurrences, because a decision expires on the version"`
	Waiting             bool    `json:"waiting" doc:"Whether a second person has to agree"`
}

// registerReaffirmDecision re-makes everything one decision covers.
func registerReaffirmDecision(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "reaffirm-decision", Method: http.MethodPost,
		Path:    "/v1/decisions/{id}/reaffirmation",
		Summary: "Re-affirm everything one decision covers",
		Description: "Re-makes every occurrence of this decision that stopped applying because an " +
			"upstream version moved, at the versions each occurrence has now, as one act with one " +
			"reasoning.\n\n" +
			"Deciding is bulk-capable and re-deciding was not. A team answering one kernel " +
			"issue writes one decision over all of its occurrences in one action; when the kernel " +
			"moves, those lapse, and restoring them was one request each with a separately " +
			"typed justification.\n\n" +
			"Only the person who made the original may do this. It normally needs no second " +
			"approver, for the reason the single form does not: two people already agreed, and " +
			"a version upgrade is a prompt to re-check rather than a new decision.\n\n" +
			"One act, one approval. Where any occurrence would need approval again — nothing was " +
			"ever agreed to, or the issue is rated a band worse since it was agreed to and " +
			"the decision is one a severity bears on — the whole act does. An approver works at the unit " +
			"the proposer acted at. A severity bears on every decision except `already-fixed`, " +
			"and `not-applicable` because the component or the vulnerable code is not present " +
			"or not in the execute path.\n\n" +
			"Bounded unless it is a promise to upgrade. The issues it covers count against " +
			"`triage.agreed-issues` where nothing goes back to an approver, and against " +
			"`triage.review-issues` where anything does; the findings it writes count against " +
			"`triage.write-ceiling`.\n\n" +
			"A lead past its end of life is not re-made, and a decision with no other occurrence is " +
			"refused with 409.\n\n" +
			"An occurrence that is open nowhere any more is not re-made, which is a finding that " +
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
		// this is comes from the decision being re-made rather than from the
		// request.
		made, err := store.ReaffirmDecision(ctx, subject, triage.ReaffirmingDecision{
			PreviousDecisionID: input.ID,
			Reasoning:          input.Body.Reasoning,
			By:                 subject.ID,
		})
		if err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchDecision()
			}
			return nil, core.RefusedDecision(in.Logger, err)
		}
		return &struct{ Body ReaffirmedBody }{Body: reaffirmedBody(made)}, nil
	})
}

func decisionBody(c triage.Decision, proposedBy, proposedByName string) DecisionBody {
	body := DecisionBody{
		ID: c.ID, Kind: core.DecisionKind(c.Kind), ProposedBy: proposedBy, ProposedByName: proposedByName,
		ProposedAt: core.Stamp(c.ProposedAt),
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
			DecisionOccurrenceID: row.DecisionOccurrenceID, DecisionOccurrenceIDs: row.DecisionOccurrenceIDs,
			Vulnerability: row.Vulnerability, Severity: row.Severity,
			ExploitedHere: row.ExploitedHere, Exploited: row.Exploited, FixedIn: row.FixedIn,
			Description: row.Description, Why: row.Why,
		})
	}
	return body
}
