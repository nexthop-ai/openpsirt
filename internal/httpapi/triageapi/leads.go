// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// LeadDecisionBody is a decision about a lead.
type LeadDecisionBody struct {
	Outcome   core.LeadOutcome `json:"outcome" doc:"What the lead is: dismissed, not a security issue, or confirmed as a real flaw"`
	Reason    core.LeadReason  `json:"reason,omitempty" doc:"Why it is dismissed. Required when it is, and refused otherwise"`
	Reasoning string           `json:"reasoning" minLength:"1" doc:"The reasoning, in markdown. Somebody else has to agree with a dismissal"`
}

// leadDecisionPath is the decision about one lead, addressed by its occurrence on
// one build. A rule's name holds a slash, so the lead is addressed by its
// occurrence alone rather than under its issue.
const leadDecisionPath = "/v1/products/{product}/branches-and-tags/{stream}/variants/{variant}/code-findings/{occurrence}/decision"

// errLeadClosed refuses a decision about a lead somebody stated was fixed.
var errLeadClosed = errors.New("closed")

func registerLeadDecisions(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "decide-lead", Method: http.MethodPost,
		Path:    leadDecisionPath,
		Summary: "Record a triage decision for a code finding",
		Description: "Records what a code finding is: `dismissed`, `not-security` or `confirmed`.\n\n" +
			"`dismissed` requires a `reason`: `false_positive`, `wont_fix`, `used_in_tests` or " +
			"`mitigated`. A dismissal and `not-security` take effect once somebody else holding " +
			"`approver` and `internal-read` on the product agrees; `confirmed` takes effect at once.\n\n" +
			"The decision covers the code finding on every stream and variant it is seen on, and every code finding " +
			"another analyzer reports as the same flaw on the build that nothing answers yet, as one " +
			"decision agreed to once. A code finding that " +
			"is fixed is refused: it opens again where it is seen again. A code finding recorded as a flaw " +
			"is refused with 409, because its flaw is judged instead.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "", access.InternalTriage), func(ctx context.Context, input *struct {
		Product    string `path:"product"`
		Stream     string `path:"stream"`
		Variant    string `path:"variant"`
		Occurrence string `path:"occurrence" doc:"The lead's occurrence identity"`
		Body       LeadDecisionBody
	}) (*struct{ Body core.DecisionOccurrenceBody }, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		named, err := core.LocatedVisibly(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		target, err := core.TargetRow(ctx, in, named.StreamID, named.VariantID)
		if err != nil {
			return nil, err
		}
		lead, err := finding.NewStore(in.DB.DB).LeadAt(ctx, subject, target.ID, input.Occurrence)
		if err == nil && lead.ClosedAt != nil {
			err = errLeadClosed
		}
		switch {
		case errors.Is(err, errLeadClosed):
			return nil, huma.Error409Conflict("that lead is fixed, and opens again where it is seen again")
		case err != nil:
			return nil, core.Absent(in.Logger, err, "that lead could not be looked up", core.NoSuchFinding)
		}
		first := triage.Proposal{
			Occurrence: triage.Occurrence{
				ProductID: named.ProductID, VulnerabilityID: lead.VulnerabilityID,
				OccurrenceIdentity: lead.OccurrenceIdentity, Visibility: lead.Visibility, Kind: kind.Analysis,
			},
			Outcome:       triage.Outcome(input.Body.Outcome),
			Justification: triage.Justification(input.Body.Reason),
			Reasoning:     input.Body.Reasoning,
			By:            subject.ID,
			MadeOn:        []int64{target.ID},
		}
		// One decision over the lead and every lead that is the same flaw and
		// that nothing answers yet, worked out where the decision is written.
		occurrence, err := store.ProposeGrouped(ctx, subject, first, func(ctx context.Context, tx bun.IDB) ([]triage.Occurrence, error) {
			// Asked where the decision is written: a hand-off landing first
			// makes the lead its flaw's.
			if err := analysis.Answerable(ctx, tx, subject, named.ProductID, lead); err != nil {
				return nil, err
			}
			kin, err := analysis.Unanswered(ctx, tx, subject, named.ProductID, lead.ID)
			if err != nil {
				return nil, err
			}
			occurrences := make([]triage.Occurrence, 0, len(kin))
			for _, k := range kin {
				also := first.Occurrence
				also.VulnerabilityID, also.OccurrenceIdentity, also.Visibility = k.VulnerabilityID, k.Occurrence, k.Visibility
				occurrences = append(occurrences, also)
			}
			return occurrences, nil
		})
		switch {
		case errors.Is(err, analysis.ErrHandedOff), errors.Is(err, finding.ErrLeadPastEndOfLife):
			return nil, huma.Error409Conflict(err.Error())
		case errors.Is(err, finding.ErrNoOpenFinding):
			return nil, core.NoSuchFinding()
		}
		if err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}
		body := core.DecisionOccurrenceBodyOf(*occurrence)
		body.Reasoning = input.Body.Reasoning
		return &struct{ Body core.DecisionOccurrenceBody }{Body: body}, nil
	})
}

// LeadFixedBody is what closing a lead as fixed did.
type LeadFixedBody struct {
	At string `json:"at" format:"date-time" doc:"When it was closed"`
}

func registerLeadFixed(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "fix-lead", Method: http.MethodPost,
		Path:    "/v1/products/{product}/branches-and-tags/{stream}/variants/{variant}/code-findings/{occurrence}/fixed",
		Summary: "Close a code finding as fixed",
		Description: "Closes a code finding on one build because it is fixed there. The code finding has to be one " +
			"the newest comparable run did not see: a code finding a run still sees is refused with 409. " +
			"`because` says what fixed it, and is required.\n\n" +
			"`fixed_in` names the build that fixed it, as the run of the code finding's series on this build " +
			"that analyzed it: an applied, comparable run built at or after the first run that did not " +
			"see the code finding, which the code finding's evidence names as `not_seen_run`. Any other run is refused " +
			"with 422.\n\n" +
			"A code finding seen again opens anew at the same occurrence.",
		Tags: []string{"Triage"},
	}, core.PerProduct, "", access.InternalTriage), func(ctx context.Context, input *struct {
		Product    string `path:"product"`
		Stream     string `path:"stream"`
		Variant    string `path:"variant"`
		Occurrence string `path:"occurrence" doc:"The lead's occurrence identity"`
		Body       struct {
			Because string `json:"because" minLength:"1" doc:"What fixed it, in markdown"`
			FixedIn int64  `json:"fixed_in" minimum:"1" doc:"The run whose build fixed it"`
		}
	}) (*struct{ Body LeadFixedBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		named, err := core.LocatedVisibly(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		target, err := core.TargetRow(ctx, in, named.StreamID, named.VariantID)
		if err != nil {
			return nil, err
		}
		done, err := finding.NewStore(in.DB.DB).FixLead(ctx, subject, target.ID, input.Occurrence, input.Body.Because,
			input.Body.FixedIn)
		switch {
		case errors.Is(err, finding.ErrStillSeen), errors.Is(err, finding.ErrLeadPastEndOfLife):
			return nil, huma.Error409Conflict(err.Error())
		case errors.Is(err, finding.ErrNoReason), errors.Is(err, finding.ErrNotAFixingRun):
			return nil, core.Asked(in.Logger, err)
		case errors.Is(err, finding.ErrNothingOpenThere), errors.Is(err, access.ErrDenied):
			return nil, core.NoSuchFinding()
		case err != nil:
			return nil, core.WentWrong(in.Logger, "that lead could not be closed", err)
		}
		return &struct{ Body LeadFixedBody }{Body: LeadFixedBody{At: core.Stamp(done.At)}}, nil
	})
}
