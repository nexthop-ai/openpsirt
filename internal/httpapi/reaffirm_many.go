// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// LapsedRowBody is one row of the findings list somebody picked.
type LapsedRowBody struct {
	Stream        string `json:"stream" minLength:"1" doc:"The branch or tag of the build the row was read in"`
	Variant       string `json:"variant" minLength:"1" doc:"The variant of that build"`
	Vulnerability string `json:"vulnerability" minLength:"1" doc:"The issue, by name"`
	Component     string `json:"component" minLength:"1" doc:"The component the row names. Any binary of a source package names all of them"`
	Version       string `json:"version,omitempty" doc:"The version, where the build ships that name at more than one"`
	Ecosystem     string `json:"ecosystem,omitempty" doc:"The ecosystem, where the build holds one name at one version as two components"`
	Namespace     string `json:"namespace,omitempty" doc:"The namespace, where the build holds one name at one version in one ecosystem as two components"`
}

// registerReaffirmMany re-makes every lapsed claim behind a selection.
func registerReaffirmMany(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "reaffirm-many", Method: http.MethodPost,
		Path:    "/v1/products/{product}/reaffirmations",
		Summary: "Re-affirm many lapsed claims",
		Description: "Re-makes every lapsed claim at the findings named, as one act with one " +
			"reasoning. Name the rows picked from the findings list; the claims behind them " +
			"are resolved here. A row's claim is one whose decision at any of the row's places " +
			"lapsed and has not been replaced since.\n\n" +
			"Each claim is re-made whole, exactly as re-affirming it alone does: every lapsed " +
			"place at the versions it has now, keeping the claim's own outcome, justification " +
			"and dates, and carrying its earlier agreement.\n\n" +
			"Whether a second person has to agree is decided per claim, by the rules " +
			"re-affirming one claim follows. `waiting` on each entry says which.\n\n" +
			"Only the person who made a claim may re-affirm it. Where somebody else made any of " +
			"them the whole act is refused, naming the issues, so they can be taken out of the " +
			"selection.\n\n" +
			"Bounded. At most 2000 rows per request, and every finding the act writes, " +
			"across every claim, counts against `triage.together-cap`. A promise to upgrade " +
			"is not counted. `reasoning` is required.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    struct {
			Findings  []LapsedRowBody `json:"findings" minItems:"1" maxItems:"2000" doc:"The rows picked"`
			Reasoning string          `json:"reasoning" minLength:"1" doc:"The reason every one of them still holds, in markdown"`
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

		// A build is looked up once however many rows name it: a kernel
		// selection is hundreds of rows in one build.
		type build struct{ stream, variant string }
		targets := map[build]int64{}
		products := map[build]int64{}
		at := make([]triage.LapsedAt, 0, len(input.Body.Findings))
		for _, row := range input.Body.Findings {
			key := build{row.Stream, row.Variant}
			if _, seen := targets[key]; !seen {
				named, err := locatedVisibly(ctx, in, subject, input.Product, row.Stream, row.Variant)
				if err != nil {
					return nil, err
				}
				target, err := targetRow(ctx, in, named.StreamID, named.VariantID)
				if err != nil {
					return nil, err
				}
				targets[key] = target.ID
				products[key] = named.ProductID
			}
			issue, err := issueHere(ctx, in, subject, products[key], row.Vulnerability)
			if err != nil {
				return nil, err
			}
			component, err := componentCarrying(ctx, in, subject, targets[key], issue,
				row.Component, graph.Choice{
					Version: row.Version, Ecosystem: row.Ecosystem, Namespace: row.Namespace,
				}, func(error) error { return noSuchFinding() })
			if err != nil {
				return nil, err
			}
			at = append(at, triage.LapsedAt{
				TargetID: targets[key], ComponentID: component, VulnerabilityID: issue,
			})
		}

		cap, err := setting.NewStore(in.DB.DB).Count(ctx, setting.TogetherCap,
			triage.DefaultTogetherCap)
		if err != nil {
			return nil, wentWrong(in.Logger, "the limit on one action could not be read", err)
		}
		made, err := store.ReaffirmMany(ctx, subject, triage.ReaffirmingMany{
			At: at, Reasoning: input.Body.Reasoning, By: subject.ID, Cap: cap,
		})
		if err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchFinding()
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
