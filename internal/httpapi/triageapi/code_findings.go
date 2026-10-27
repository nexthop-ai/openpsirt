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

// CodeFindingDecisionBody is a decision about a code finding.
type CodeFindingDecisionBody struct {
	Outcome   core.CodeFindingOutcome `json:"outcome" doc:"What the code finding is: dismissed, not a security issue, or confirmed as a real flaw"`
	Reason    core.CodeFindingReason  `json:"reason,omitempty" doc:"Why it is dismissed. Required when it is, and refused otherwise"`
	Reasoning string                  `json:"reasoning" minLength:"1" doc:"The reasoning, in markdown. Somebody else has to agree with a dismissal"`
}

// codeFindingDecisionPath is the decision about one code finding, addressed by its occurrence on
// one build. A rule's name holds a slash, so the code finding is addressed by its
// occurrence alone rather than under its issue.
const codeFindingDecisionPath = "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/decision"

// errCodeFindingClosed refuses a decision about a code finding somebody stated was fixed.
var errCodeFindingClosed = errors.New("closed")

func registerCodeFindingDecisions(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "decide-code-finding", Method: http.MethodPost,
		Path:    codeFindingDecisionPath,
		Summary: "Record a triage decision for a code finding",
		Description: "Records what a code finding is: `dismissed`, `not-security` or `confirmed`.\n\n" +
			"`dismissed` requires a `reason`: `false_positive`, `wont_fix`, `used_in_tests` or " +
			"`mitigated`. A dismissal and `not-security` take effect once somebody else holding " +
			"`approver` and `internal-read` on the product agrees; `confirmed` takes effect at once.\n\n" +
			"The decision covers the code finding on every branch or tag and variant it is seen on, and every code finding " +
			"another analyzer reports as the same flaw on the build that nothing answers yet, as one " +
			"decision agreed to once. A code finding that " +
			"is fixed is refused: it opens again where it is seen again. A code finding recorded as a flaw " +
			"is refused with 409, because its flaw is judged instead.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "", access.InternalTriage), func(ctx context.Context, input *struct {
		Product     string `path:"product"`
		BranchOrTag string `path:"branch_or_tag"`
		Variant     string `path:"variant"`
		Occurrence  string `path:"occurrence" doc:"The code finding's occurrence identity"`
		Body        CodeFindingDecisionBody
	}) (*struct{ Body core.DecisionOccurrenceBody }, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		named, err := core.LocatedVisibly(ctx, in, subject, input.Product, input.BranchOrTag, input.Variant)
		if err != nil {
			return nil, err
		}
		build, err := core.BuildRow(ctx, in, named.BranchOrTagID, named.VariantID)
		if err != nil {
			return nil, err
		}
		codeFinding, err := finding.NewStore(in.DB.DB).CodeFindingAt(ctx, subject, build.ID, input.Occurrence)
		if err == nil && codeFinding.ClosedAt != nil {
			err = errCodeFindingClosed
		}
		switch {
		case errors.Is(err, errCodeFindingClosed):
			return nil, huma.Error409Conflict("that code finding is fixed, and opens again where it is seen again")
		case err != nil:
			return nil, core.Absent(in.Logger, err, "that code finding could not be looked up", core.NoSuchFinding)
		}
		first := triage.Proposal{
			Occurrence: triage.Occurrence{
				ProductID: named.ProductID, VulnerabilityID: codeFinding.VulnerabilityID,
				OccurrenceIdentity: codeFinding.OccurrenceIdentity, Visibility: codeFinding.Visibility, Kind: kind.Analysis,
			},
			Outcome:       triage.Outcome(input.Body.Outcome),
			Justification: triage.Justification(input.Body.Reason),
			Reasoning:     input.Body.Reasoning,
			By:            subject.ID,
			MadeOn:        []int64{build.ID},
		}
		// One decision over the code finding and every code finding that is the same flaw and
		// that nothing answers yet, worked out where the decision is written.
		occurrence, err := store.ProposeGrouped(ctx, subject, first, func(ctx context.Context, tx bun.IDB) ([]triage.Occurrence, error) {
			// Asked where the decision is written: a flaw record landing first
			// makes the code finding its flaw's.
			if err := analysis.Answerable(ctx, tx, subject, named.ProductID, codeFinding); err != nil {
				return nil, err
			}
			kin, err := analysis.Unanswered(ctx, tx, subject, named.ProductID, codeFinding.ID)
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
		case errors.Is(err, analysis.ErrRecordedAsFlaw), errors.Is(err, finding.ErrCodeFindingPastEndOfLife):
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

// CodeFindingFixedBody is what closing a code finding as fixed did.
type CodeFindingFixedBody struct {
	At string `json:"at" format:"date-time" doc:"When it was closed"`
}

func registerCodeFindingFixed(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "fix-code-finding", Method: http.MethodPost,
		Path:    "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/fixed",
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
		Product     string `path:"product"`
		BranchOrTag string `path:"branch_or_tag"`
		Variant     string `path:"variant"`
		Occurrence  string `path:"occurrence" doc:"The code finding's occurrence identity"`
		Body        struct {
			Because string `json:"because" minLength:"1" doc:"What fixed it, in markdown"`
			FixedIn int64  `json:"fixed_in" minimum:"1" doc:"The run whose build fixed it"`
		}
	}) (*struct{ Body CodeFindingFixedBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		named, err := core.LocatedVisibly(ctx, in, subject, input.Product, input.BranchOrTag, input.Variant)
		if err != nil {
			return nil, err
		}
		build, err := core.BuildRow(ctx, in, named.BranchOrTagID, named.VariantID)
		if err != nil {
			return nil, err
		}
		done, err := finding.NewStore(in.DB.DB).FixCodeFinding(ctx, subject, build.ID, input.Occurrence, input.Body.Because,
			input.Body.FixedIn)
		switch {
		case errors.Is(err, finding.ErrStillSeen), errors.Is(err, finding.ErrCodeFindingPastEndOfLife):
			return nil, huma.Error409Conflict(err.Error())
		case errors.Is(err, finding.ErrNoReason), errors.Is(err, finding.ErrNotAFixingRun):
			return nil, core.Asked(in.Logger, err)
		case errors.Is(err, finding.ErrNothingOpenThere), errors.Is(err, access.ErrDenied):
			return nil, core.NoSuchFinding()
		case err != nil:
			return nil, core.WentWrong(in.Logger, "that code finding could not be closed", err)
		}
		return &struct{ Body CodeFindingFixedBody }{Body: CodeFindingFixedBody{At: core.Stamp(done.At)}}, nil
	})
}
