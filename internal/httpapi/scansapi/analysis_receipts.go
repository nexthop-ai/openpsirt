// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// AnalysisReceiptBody is the record of one analyzer run. It counts results
// and never names one.
type AnalysisReceiptBody struct {
	RunID      int64          `json:"run_id" doc:"The run this upload became"`
	Series     string         `json:"series" doc:"The series the run belongs to"`
	Commit     string         `json:"commit,omitempty" doc:"The commit analyzed"`
	BuiltAt    string         `json:"built_at" doc:"The build time the run states, or the time it arrived where it states none"`
	ReceivedAt string         `json:"received_at" doc:"The moment it arrived here"`
	Status     core.RunStatus `json:"status" doc:"What became of it: waiting for the build's inventory to be read, applied, superseded by a run built later, held because it would mark too much not reproduced at once, or failed"`
	Failure    string         `json:"failure,omitempty" doc:"Why the run could not be applied, where it could not"`
	// Comparable is absent until the run is applied.
	Comparable    *bool          `json:"comparable,omitempty" doc:"Whether the results this run did not report count as not reproduced. Absent until it is applied"`
	NotComparable core.RunReason `json:"not_comparable,omitempty" doc:"Why they do not, where they do not"`
	Baseline      bool           `json:"baseline,omitempty" doc:"Whether this was the series' first comparable run"`
	Tool          string         `json:"tool,omitempty" doc:"The analyzer that ran"`
	ToolVersion   string         `json:"tool_version,omitempty" doc:"Its version"`
	// Counts is absent until the run has been read.
	Counts *analysis.Receipt `json:"counts,omitempty" doc:"What the run did. Absent until it has been read"`
}

// AnalysisReceiptsOutput is a page of analyzer runs sent against a build.
type AnalysisReceiptsOutput struct {
	Body struct {
		Items []AnalysisReceiptBody `json:"items"`
		Total int                   `json:"total"`
	}
}

func registerAnalysisReceipts(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-analyses", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/analyses",
		Summary: "List uploaded analyzer runs and their status",
		Description: "Returns analyzer runs newest first, each with its status and, once applied, " +
			"whether it was comparable and how many results it opened, saw again and did not see.\n\n" +
			"An API key sees every run on a build it may upload to. A person sees them where they " +
			"read internal findings in the product.",
		Tags: []string{"Ingest"},
	}, core.AnySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"The number returned"`
		Offset  int    `query:"offset" minimum:"0" doc:"The number skipped"`
	}) (*AnalysisReceiptsOutput, error) {
		subject, named, err := core.ReadableBuild(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		out := &AnalysisReceiptsOutput{}
		out.Body.Items = []AnalysisReceiptBody{}
		target, err := catalog.NewStore(in.DB.DB).ExistingTarget(ctx, named.StreamID, named.VariantID)
		switch {
		case errors.Is(err, catalog.ErrNotFound):
			return out, nil
		case err != nil:
			return nil, core.WentWrong(in.Logger, "that build could not be looked up", err)
		}
		sent, total, err := series.NewStore(in.DB.DB).Receipts(ctx, subject, named.ProductID, target.ID,
			kind.Analysis, access.Internal, input.Limit, input.Offset)
		switch {
		case errors.Is(err, access.ErrDenied):
			return nil, core.NothingScannedThere()
		case err != nil:
			return nil, core.WentWrong(in.Logger, "the analyzer runs could not be read", err)
		}
		for _, s := range sent {
			body := AnalysisReceiptBody{
				RunID: s.ID, Series: s.SeriesName, Commit: s.SourceCommit,
				BuiltAt: core.Stamp(s.BuiltAt), ReceivedAt: core.Stamp(s.ReceivedAt),
				Status: core.RunStatus(s.Status), Failure: s.Failure,
				Comparable: s.Comparable, NotComparable: core.RunReason(s.Reason), Baseline: s.Baseline,
				Tool: s.ToolName, ToolVersion: s.ToolVersion,
			}
			if s.Receipt != "" {
				var counts analysis.Receipt
				if err := json.Unmarshal([]byte(s.Receipt), &counts); err != nil {
					return nil, core.WentWrong(in.Logger, "a run's receipt could not be read", err)
				}
				body.Counts = &counts
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		out.Body.Total = total
		return out, nil
	})
}
