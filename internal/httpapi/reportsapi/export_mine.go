// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"context"
	"net/http"
	"strconv"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// registerMyClaimsExport writes out what became of the caller's own claims.
//
// The review queue's Mine tab lists every claim its reader proposed, whatever
// happened to it. The queue's own file with mine set holds only what is still
// waiting, so a file taken from that tab needs a list of its own.
func registerMyClaimsExport(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "export-my-claims", Method: http.MethodGet,
		Path:    "/v1/my-claims.{format}",
		Summary: "Export the outcomes of your own claims",
		Description: "What `GET /v1/my-claims` lists, as a file: every claim you proposed, " +
			"newest first, with what became of each and who did it, rather than one page.\n\n" +
			"Narrowed to what you may still read.",
		Tags: []string{"Triage"},
	}, core.AnyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		out := core.Exporting{
			What: "your claims",
			Header: []string{
				"claim", "proposed", "outcome", "became", "when", "by", "by name",
				"issue", "product", "product name", "stream", "stream name",
				"variant", "variant name", "component",
				"decisions", "issues", "places", "reasoning",
			},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				mine, _, err := store.Became(ctx, subject, limit, offset)
				if err != nil || len(mine) == 0 {
					return nil, err
				}
				// Described in one pass, the way the list describes them, so
				// the file and the tab name the same place for the same claim.
				decisions := make([]triage.Decision, 0, len(mine))
				actors := make([]int64, 0, len(mine))
				for _, row := range mine {
					decisions = append(decisions, row.Decision)
					if row.By != 0 {
						actors = append(actors, row.By)
					}
				}
				named, err := core.DescribeDecisions(ctx, in, store, decisions, nil)
				if err != nil {
					return nil, err
				}
				who, err := core.WhoSigned(ctx, in.DB.DB, actors)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(mine))
				for i, row := range mine {
					when, by, byName := "", "", ""
					if row.When != nil {
						when = core.Stamp(*row.When)
					}
					if row.By != 0 {
						by, byName = who.Identity(row.By), who.Label(row.By)
					}
					// The build as well as the product, as the tab names it: two
					// claims on one component in two builds are otherwise told
					// apart by number alone.
					var product, productName, stream, streamName, variant, variantName, component string
					if where := named[i].Finding; where != nil {
						product, productName = where.Product, where.ProductName
						stream, streamName = where.Stream, where.StreamName
						variant, variantName = where.Variant, where.VariantName
						component = where.Component + " " + where.Version
					}
					rows = append(rows, []string{
						strconv.FormatInt(row.Claim.ID, 10),
						core.Stamp(row.Decision.ProposedAt),
						string(row.Claim.Outcome), string(row.Happened), when, by, byName,
						named[i].Place.Vulnerability, product, productName,
						stream, streamName, variant, variantName, component,
						strconv.Itoa(row.Rows), strconv.Itoa(row.Issues), strconv.Itoa(row.Places),
						row.Reasoning,
					})
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			core.WriteExport(writer, input.Format, "my-claims", out)
		}}, nil
	})
}
