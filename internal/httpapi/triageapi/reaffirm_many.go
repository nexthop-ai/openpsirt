// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// ToReaffirmBody is one lapsed decision of yours that nothing has replaced.
type ToReaffirmBody struct {
	Decision           DecisionBody                `json:"decision"`
	DecisionOccurrence core.DecisionOccurrenceBody `json:"decision_occurrence"`
	Occurrence         core.OccurrenceBody         `json:"occurrence"`
	Reasoning          string                      `json:"reasoning" doc:"The reasoning the decision rested on"`
	Rows               int                         `json:"rows" doc:"The number of its occurrences that lapsed, counting one occurrence at two versions twice"`
	Issues             int                         `json:"issues" doc:"The number of distinct issues those cover"`
	Occurrences        int                         `json:"occurrences" doc:"The number of distinct occurrences those cover"`
	Finding            *core.FindingRefBody        `json:"finding,omitempty" doc:"The finding at the representative occurrence. Absent where no open finding sits there"`
	LapsedAt           string                      `json:"lapsed_at,omitempty" doc:"When it lapsed"`
	CodeMoved          bool                        `json:"code_moved" doc:"Whether a version moved under it"`
	// Was and Now are about the first issue rated worse, where one was.
	RatedWorse bool   `json:"rated_worse" doc:"Whether an issue the decision covers now sits in a higher band than when the decision was made, on a decision a severity bears on"`
	Was        string `json:"was,omitempty" doc:"How bad that issue was judged to be when the decision was made, or the representative issue where none was rated worse. Absent where it was unrated"`
	Now        string `json:"now,omitempty" doc:"How bad the same issue is judged to be here now. Absent where it is unrated"`
}

// ToReaffirmOutput is a page of lapsed decisions.
type ToReaffirmOutput struct {
	Body struct {
		Items []ToReaffirmBody `json:"items"`
		Total int              `json:"total"`
	}
}

// registerReaffirmMany lists what is yours to re-affirm and re-makes several
// of those decisions in one act.
func registerReaffirmMany(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-to-reaffirm", Method: http.MethodGet, Path: "/v1/to-reaffirm",
		Summary: "List your lapsed decisions",
		Description: "Returns the decisions you proposed that lapsed and that nothing has replaced, " +
			"the most recently written first: the decisions that are yours to re-affirm. " +
			"`product` narrows them to one product.\n\n" +
			"A decision lapses when a version moves under it, and when the issue is rated into a " +
			"higher band on a decision a severity bears on. `code_moved` and `rated_worse` say " +
			"which, and both can hold.\n\n" +
			"Narrowed to the decisions you may still argue about, every lapsed occurrence of them. A " +
			"lapsed occurrence at a lead past its end of life is not counted, and a decision with no " +
			"other is not listed.",
		Tags: []string{"Triage"},
	}, core.AnyPerson, "Answers only what you may act on."), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"A product to narrow to, by name"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset  int    `query:"offset" minimum:"0"`
	}) (*ToReaffirmOutput, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		var productID int64
		if input.Product != "" {
			product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
			if err != nil {
				return nil, err
			}
			productID = product.ID
		}
		mine, total, err := store.ToReaffirm(ctx, subject, productID, input.Limit, input.Offset)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "what is yours to re-affirm could not be read", err)
		}
		occurrences := make([]triage.DecisionOccurrence, 0, len(mine))
		for _, row := range mine {
			occurrences = append(occurrences, row.DecisionOccurrence)
		}
		named, err := core.DescribeDecisionOccurrences(ctx, in, store, occurrences, nil)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "what is yours to re-affirm could not be read", err)
		}
		out := &ToReaffirmOutput{}
		out.Body.Items = make([]ToReaffirmBody, 0, len(mine))
		for i, row := range mine {
			entry := ToReaffirmBody{
				Decision:           decisionBody(row.Decision, named[i].ProposedBy, named[i].ProposedByName),
				DecisionOccurrence: core.DecisionOccurrenceBodyOf(row.DecisionOccurrence),
				Occurrence:         named[i].Occurrence,
				Reasoning:          row.Reasoning,
				Rows:               row.Rows, Issues: row.Issues, Occurrences: row.Occurrences,
				Finding:    named[i].Finding,
				CodeMoved:  row.CodeMoved,
				RatedWorse: row.RatedWorse,
				Was:        finding.SeverityWord(row.Was),
				Now:        finding.SeverityWord(row.Now),
			}
			entry.LapsedAt = core.StampAt(row.LapsedAt)
			out.Body.Items = append(out.Body.Items, entry)
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "reaffirm-many", Method: http.MethodPost, Path: "/v1/reaffirmations",
		Summary: "Re-affirm several lapsed decisions",
		Description: "Re-makes each decision named, as one act with one reasoning. Name decisions from " +
			"`GET /v1/to-reaffirm`.\n\n" +
			"Each decision is re-made whole, exactly as re-affirming it alone does: every lapsed " +
			"occurrence at the versions it has now, keeping the decision's own outcome, justification " +
			"and dates, and carrying its earlier agreement.\n\n" +
			"Whether a second person has to agree is decided per decision, by the rules " +
			"re-affirming one decision follows. `waiting` on each entry says which.\n\n" +
			"Only the person who made a decision may re-affirm it. Where somebody else made any of " +
			"them the whole act is refused, naming the issues. A decision with no lapsed occurrence that " +
			"nothing has replaced answers as though it were not there. A lead past its end of " +
			"life is not re-made, and a decision with no other occurrence refuses the whole act with 409.\n\n" +
			"Bounded over the whole act, promises to upgrade aside. The issues it covers count " +
			"against `triage.agreed-issues` where no decision goes back to an approver, and " +
			"against `triage.review-issues` where any does; the findings it writes count " +
			"against `triage.write-ceiling`. At most 2000 decisions per request. `reasoning` is " +
			"required.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, core.AnyPerson, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		Body struct {
			Decisions []int64 `json:"decisions" minItems:"1" maxItems:"2000" doc:"The lapsed decisions to re-make"`
			Reasoning string  `json:"reasoning" minLength:"1" doc:"The reason every one of them still holds, in markdown"`
		}
	}) (*struct {
		Body struct {
			Decisions []ReaffirmedBody `json:"decisions" doc:"One entry per decision re-made"`
		}
	}, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		made, err := store.ReaffirmMany(ctx, subject, triage.ReaffirmingMany{
			DecisionIDs: input.Body.Decisions, Reasoning: input.Body.Reasoning,
			By: subject.ID,
		})
		if err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchDecision()
			}
			return nil, core.RefusedDecision(in.Logger, err)
		}
		out := &struct {
			Body struct {
				Decisions []ReaffirmedBody `json:"decisions" doc:"One entry per decision re-made"`
			}
		}{}
		out.Body.Decisions = make([]ReaffirmedBody, 0, len(made))
		for _, one := range made {
			out.Body.Decisions = append(out.Body.Decisions, reaffirmedBody(one))
		}
		return out, nil
	})
}

// reaffirmedBody is one re-made decision as the API reports it.
func reaffirmedBody(made triage.Reaffirmed) ReaffirmedBody {
	return ReaffirmedBody{
		PreviousDecisionID: made.PreviousDecisionID, DecisionID: made.DecisionID,
		DecisionOccurrences: made.DecisionOccurrences, Occurrences: made.Occurrences, Waiting: made.Waiting,
	}
}
