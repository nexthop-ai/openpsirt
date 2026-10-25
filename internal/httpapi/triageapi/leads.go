// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/trail"
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
			"The decision covers the lead on every stream and variant it is seen on, and every lead " +
			"another analyzer reports as the same flaw on the build that nothing answers yet, as one " +
			"claim agreed to once. A lead that " +
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
		kin, err := analysis.Unanswered(ctx, in.DB.DB, subject, named.ProductID, lead.ID)
		if err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}
		first := triage.Proposal{
			Place: triage.Place{
				ProductID: named.ProductID, VulnerabilityID: lead.VulnerabilityID,
				PlaceIdentity: lead.PlaceIdentity, Visibility: lead.Visibility, Kind: kind.Analysis,
			},
			Outcome:       triage.Outcome(input.Body.Outcome),
			Justification: triage.Justification(input.Body.Reason),
			Reasoning:     input.Body.Reasoning,
			By:            subject.ID,
			MadeOn:        []int64{target.ID},
		}
		var decision *triage.Decision
		if len(kin) == 0 {
			decision, err = store.Propose(ctx, subject, first)
		} else {
			// One claim over the lead and every lead that is the same flaw,
			// agreed to once.
			proposals := []triage.Proposal{first}
			for _, k := range kin {
				also := first
				also.Place.VulnerabilityID, also.Place.PlaceIdentity, also.Place.Visibility =
					k.VulnerabilityID, k.Place, k.Visibility
				proposals = append(proposals, also)
			}
			var recorded []*triage.Decision
			if recorded, err = store.ProposeMany(ctx, subject, proposals); err == nil {
				decision = recorded[0]
			}
		}
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

// LeadEscalatedBody is a lead pulled into the queue.
type LeadEscalatedBody struct {
	At string `json:"at" format:"date-time" doc:"When it was pulled in. Pulled in again, the first time stands"`
}

func registerLeadEscalation(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "escalate-lead", Method: http.MethodPost,
		Path:    "/v1/products/{product}/leads/{place}/escalation",
		Summary: "Pull a lead into the queue",
		Description: "Takes a lead out of the baseline and into the queue on every build of the " +
			"product it is on. A lead already pulled in keeps when it first was, and a lead " +
			"not in the baseline is unchanged.",
		Tags: []string{"Triage"},
	}, core.PerProduct, "", access.InternalTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Place   string `path:"place" doc:"The lead's place identity"`
	}) (*struct{ Body LeadEscalatedBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		done, err := analysis.Escalate(ctx, in.DB.DB, subject, product.ID, input.Place, time.Now())
		switch {
		case errors.Is(err, finding.ErrNothingOpenThere), errors.Is(err, access.ErrDenied):
			return nil, core.NoSuchFinding()
		case err != nil:
			return nil, core.WentWrong(in.Logger, "that lead could not be pulled in", err)
		}
		return &struct{ Body LeadEscalatedBody }{Body: LeadEscalatedBody{At: core.Stamp(done.At)}}, nil
	})
}

// ImportantPathsBody is the paths whose baseline leads are in a product's
// queue.
type ImportantPathsBody struct {
	Paths []string `json:"paths" maxItems:"500" doc:"Path prefixes from the top of the checkout. A lead at or under one is in the queue from its first run"`
}

func registerImportantPaths(api huma.API, in core.Deps) {
	const path = "/v1/products/{product}/important-paths"
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-important-paths", Method: http.MethodGet, Path: path,
		Summary:     "Get a product's important paths",
		Description: "Returns the path prefixes whose leads are in the queue from their first run, in order.",
		Tags:        []string{"Triage"},
	}, core.PerProduct, "", access.InternalRead, access.InternalTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*struct{ Body ImportantPathsBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		if !subject.Reads(access.Internal, product.ID) {
			// The product resolved, so the caller can see it: refused for
			// the role.
			return nil, huma.Error403Forbidden("not authorized")
		}
		held, err := analysis.ImportantPaths(ctx, in.DB.DB, product.ID)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the important paths could not be read", err)
		}
		return &struct{ Body ImportantPathsBody }{Body: ImportantPathsBody{Paths: held}}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "set-important-paths", Method: http.MethodPut, Path: path,
		Summary: "Set a product's important paths",
		Description: "Replaces the path prefixes whose leads are in the queue from their first run. " +
			"A lead in the baseline at or under one enters the queue at once, and leaves it again " +
			"where its path is taken off.\n\n" +
			"Refused, naming the path, where one is empty, climbs out of the checkout or is named " +
			"twice. Recorded in the administrative trail.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "", access.InternalTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    ImportantPathsBody
	}) (*struct{}, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		named, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		if !subject.Holds(access.InternalTriage, named.ID) {
			return nil, huma.Error403Forbidden("not authorized")
		}
		paths, err := analysis.CleanImportantPaths(input.Body.Paths)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity(err.Error())
		}
		return &struct{}{}, core.Changing(ctx, in.DB, in.Logger, func(ctx context.Context, tx bun.Tx) error {
			product, err := catalog.NewStore(tx).ProductByName(ctx, input.Product)
			if err != nil {
				return core.Absent(in.Logger, err, "that product could not be looked up", core.NoSuchProduct)
			}
			was, err := analysis.ImportantPaths(ctx, tx, product.ID)
			if err != nil {
				return core.WentWrong(in.Logger, "the important paths could not be read", err)
			}
			if err := analysis.ReplaceImportantPaths(ctx, tx, product.ID, paths); err != nil {
				return core.WentWrong(in.Logger, "the important paths could not be recorded", err)
			}
			if err := core.Noted(ctx, tx, trail.Setting, "important paths of "+product.Name,
				trail.Said(strings.Join(was, ", "), true), trail.Said(strings.Join(paths, ", "), true)); err != nil {
				return core.NotRecorded(in.Logger, err)
			}
			return nil
		})
	})
}
