// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// ToReaffirmBody is one lapsed claim of yours that nothing has replaced.
type ToReaffirmBody struct {
	Claim     ClaimBody       `json:"claim"`
	Decision  DecisionBody    `json:"decision"`
	Place     PlaceBody       `json:"place"`
	Reasoning string          `json:"reasoning" doc:"The reasoning the claim rested on"`
	Decisions int             `json:"decisions" doc:"The number of its rows that lapsed"`
	Issues    int             `json:"issues" doc:"The number of distinct issues those cover"`
	Places    int             `json:"places" doc:"The number of distinct places those cover"`
	Finding   *FindingRefBody `json:"finding,omitempty" doc:"The representative decision's subject. Absent where no open finding sits at its place"`
	LapsedAt  string          `json:"lapsed_at,omitempty" doc:"When it lapsed"`
	CodeMoved bool            `json:"code_moved" doc:"Whether a version moved under it"`
	// Was and Now are about the first issue rated worse, where one was.
	RatedWorse bool   `json:"rated_worse" doc:"Whether an issue the claim covers now sits in a higher band than when the claim was made, on a claim a severity bears on"`
	Was        string `json:"was,omitempty" doc:"How bad that issue was judged to be when the claim was made, or the representative issue where none was rated worse. Absent where it was unrated"`
	Now        string `json:"now,omitempty" doc:"How bad the same issue is judged to be here now. Absent where it is unrated"`
}

// ToReaffirmOutput is a page of lapsed claims.
type ToReaffirmOutput struct {
	Body struct {
		Items []ToReaffirmBody `json:"items"`
		Total int              `json:"total"`
	}
}

// registerReaffirmMany lists what is yours to re-affirm and re-makes several
// of those claims in one act.
func registerReaffirmMany(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-to-reaffirm", Method: http.MethodGet, Path: "/v1/to-reaffirm",
		Summary: "List your lapsed claims",
		Description: "Returns the claims you proposed that lapsed and that nothing has replaced, " +
			"the most recently written first: the claims that are yours to re-affirm. " +
			"`product` narrows them to one product.\n\n" +
			"A claim lapses when a version moves under it, and when the issue is rated into a " +
			"higher band on a claim a severity bears on. `code_moved` and `rated_worse` say " +
			"which, and both can hold.\n\n" +
			"Narrowed to the claims you may still argue about, every lapsed row of them.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may act on."), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"A product to narrow to, by name"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset  int    `query:"offset" minimum:"0"`
	}) (*ToReaffirmOutput, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		var productID int64
		if input.Product != "" {
			product, err := productNamedVisibly(ctx, in, subject, input.Product)
			if err != nil {
				return nil, err
			}
			productID = product.ID
		}
		mine, total, err := store.ToReaffirm(ctx, subject, productID, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "what is yours to re-affirm could not be read", err)
		}
		decisions := make([]triage.Decision, 0, len(mine))
		for _, row := range mine {
			decisions = append(decisions, row.Decision)
		}
		named, err := describeDecisions(ctx, in, store, decisions, nil)
		if err != nil {
			return nil, wentWrong(in.Logger, "what is yours to re-affirm could not be read", err)
		}
		out := &ToReaffirmOutput{}
		out.Body.Items = make([]ToReaffirmBody, 0, len(mine))
		for i, row := range mine {
			entry := ToReaffirmBody{
				Claim:     claimBody(row.Claim, named[i].ProposedBy, named[i].ProposedByName),
				Decision:  decisionBody(row.Decision),
				Place:     named[i].Place,
				Reasoning: row.Reasoning,
				Decisions: row.Rows, Issues: row.Issues, Places: row.Places,
				Finding:    named[i].Finding,
				CodeMoved:  row.CodeMoved,
				RatedWorse: row.RatedWorse,
				Was:        finding.SeverityWord(row.Was),
				Now:        finding.SeverityWord(row.Now),
			}
			if row.LapsedAt != nil {
				entry.LapsedAt = row.LapsedAt.Format(time.RFC3339)
			}
			out.Body.Items = append(out.Body.Items, entry)
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "reaffirm-many", Method: http.MethodPost, Path: "/v1/reaffirmations",
		Summary: "Re-affirm several lapsed claims",
		Description: "Re-makes each claim named, as one act with one reasoning. Name claims from " +
			"`GET /v1/to-reaffirm`.\n\n" +
			"Each claim is re-made whole, exactly as re-affirming it alone does: every lapsed " +
			"place at the versions it has now, keeping the claim's own outcome, justification " +
			"and dates, and carrying its earlier agreement.\n\n" +
			"Whether a second person has to agree is decided per claim, by the rules " +
			"re-affirming one claim follows. `waiting` on each entry says which.\n\n" +
			"Only the person who made a claim may re-affirm it. Where somebody else made any of " +
			"them the whole act is refused, naming the issues. A claim with no lapsed row that " +
			"nothing has replaced answers as though it were not there.\n\n" +
			"Bounded over the whole act, promises to upgrade aside. The issues it covers count " +
			"against `triage.agreed-issues` where no claim goes back to an approver, and " +
			"against `triage.review-issues` where any does; the findings it writes count " +
			"against `triage.write-ceiling`. At most 2000 claims per request. `reasoning` is " +
			"required.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, anyPerson, "", triageRights()...), func(ctx context.Context, input *struct {
		Body struct {
			Claims    []int64 `json:"claims" minItems:"1" maxItems:"2000" doc:"The lapsed claims to re-make"`
			Reasoning string  `json:"reasoning" minLength:"1" doc:"The reason every one of them still holds, in markdown"`
		}
	}) (*struct {
		Body struct {
			Claims []ReaffirmedBody `json:"claims" doc:"One entry per claim re-made"`
		}
	}, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		made, err := store.ReaffirmMany(ctx, subject, triage.ReaffirmingMany{
			ClaimIDs: input.Body.Claims, Reasoning: input.Body.Reasoning,
			By: subject.ID,
		})
		if err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchClaim()
			}
			return nil, refusedDecision(in.Logger, err)
		}
		out := &struct {
			Body struct {
				Claims []ReaffirmedBody `json:"claims" doc:"One entry per claim re-made"`
			}
		}{}
		out.Body.Claims = make([]ReaffirmedBody, 0, len(made))
		for _, one := range made {
			out.Body.Claims = append(out.Body.Claims, reaffirmedBody(one))
		}
		return out, nil
	})
}

// reaffirmedBody is one re-made claim as the API reports it.
func reaffirmedBody(made triage.Reaffirmed) ReaffirmedBody {
	return ReaffirmedBody{
		PreviousClaimID: made.PreviousClaimID, ClaimID: made.ClaimID,
		Decisions: made.Decisions, Places: made.Places, Waiting: made.Waiting,
	}
}
