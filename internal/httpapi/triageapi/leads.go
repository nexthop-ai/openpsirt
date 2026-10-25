// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// LeadDecisionBody is a judgment about a lead.
type LeadDecisionBody struct {
	Outcome   core.LeadOutcome `json:"outcome" doc:"What the lead is: dismissed, not a security issue, or confirmed as a real flaw"`
	Reason    core.LeadReason  `json:"reason,omitempty" doc:"Why it is dismissed. Required when it is, and refused otherwise"`
	Reasoning string           `json:"reasoning" minLength:"1" doc:"The reasoning, in markdown. Somebody else has to agree with a dismissal"`
}

// leadDecisionPath is the judgment about one lead, addressed by its place on
// one build. A rule's name holds a slash, so the lead is addressed by its
// place alone rather than under its issue.
const leadDecisionPath = "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}/decision"

// errLeadClosed refuses a judgment about a lead somebody stated was fixed.
var errLeadClosed = errors.New("closed")

func registerLeadDecisions(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "decide-lead", Method: http.MethodPost,
		Path:    leadDecisionPath,
		Summary: "Record a triage decision for a lead",
		Description: "Records what a lead is: `dismissed`, `not-security` or `confirmed`.\n\n" +
			"`dismissed` requires a `reason`: `false_positive`, `wont_fix`, `used_in_tests` or " +
			"`mitigated`. A dismissal and `not-security` take effect once somebody else holding " +
			"`approver` and `internal-read` on the product agrees; `confirmed` takes effect at once.\n\n" +
			"The decision covers the lead on every stream and variant it is seen on. A lead that " +
			"is fixed is refused: it opens again where it is seen again.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Place   string `path:"place" doc:"The lead's place identity"`
		Body    LeadDecisionBody
	}) (*struct{ Body core.DecisionBody }, error) {
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
		lead, err := finding.NewStore(in.DB.DB).LeadAt(ctx, subject, target.ID, input.Place)
		if err == nil && lead.ClosedAt != nil {
			err = errLeadClosed
		}
		switch {
		case errors.Is(err, errLeadClosed):
			return nil, huma.Error409Conflict("that lead is fixed, and opens again where it is seen again")
		case err != nil:
			return nil, core.Absent(in.Logger, err, "that lead could not be looked up", core.NoSuchFinding)
		}
		decision, err := store.Propose(ctx, subject, triage.Proposal{
			Place: triage.Place{
				ProductID: named.ProductID, VulnerabilityID: lead.VulnerabilityID,
				PlaceIdentity: lead.PlaceIdentity, Visibility: lead.Visibility, Kind: kind.Analysis,
			},
			Outcome:       triage.Outcome(input.Body.Outcome),
			Justification: triage.Justification(input.Body.Reason),
			Reasoning:     input.Body.Reasoning,
			By:            subject.ID,
			MadeOn:        []int64{target.ID},
		})
		if err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}
		body := core.DecisionBodyOf(*decision)
		body.Reasoning = input.Body.Reasoning
		return &struct{ Body core.DecisionBody }{Body: body}, nil
	})
}

// LeadFixedBody is what closing a lead as fixed did.
type LeadFixedBody struct {
	At string `json:"at" format:"date-time" doc:"When it was closed"`
}

func registerLeadFixed(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "fix-lead", Method: http.MethodPost,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}/fixed",
		Summary: "Close a lead as fixed",
		Description: "Closes a lead on one build because it is fixed there. The lead has to be one " +
			"the newest comparable run did not see: a lead a run still sees is refused with 409. " +
			"`because` says what fixed it, and is required.\n\n" +
			"A lead seen again opens anew at the same place.",
		Tags: []string{"Triage"},
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Place   string `path:"place" doc:"The lead's place identity"`
		Body    struct {
			Because string `json:"because" minLength:"1" doc:"What fixed it, in markdown"`
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
		done, err := finding.NewStore(in.DB.DB).FixLead(ctx, subject, target.ID, input.Place, input.Body.Because)
		switch {
		case errors.Is(err, finding.ErrStillSeen):
			return nil, huma.Error409Conflict(err.Error())
		case errors.Is(err, finding.ErrNoReason):
			return nil, core.Asked(in.Logger, err)
		case errors.Is(err, finding.ErrNothingOpenThere), errors.Is(err, access.ErrDenied):
			return nil, core.NoSuchFinding()
		case err != nil:
			return nil, core.WentWrong(in.Logger, "that lead could not be closed", err)
		}
		return &struct{ Body LeadFixedBody }{Body: LeadFixedBody{At: core.Stamp(done.At)}}, nil
	})
}
