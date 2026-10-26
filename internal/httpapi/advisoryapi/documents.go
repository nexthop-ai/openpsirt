// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// DocumentBody is one third-party document a product holds statements from.
type DocumentBody struct {
	Publisher  string `json:"publisher" doc:"The publisher the document names, as it is matched"`
	Identifier string `json:"identifier,omitempty" doc:"The name the publisher gave the advisory. Absent for a VEX document, which a publisher issues one of"`
	Document   string `json:"document" doc:"The file name it last arrived as, or for an advisory a feed fetched, the address it came from"`
	Digest     string `json:"digest" doc:"SHA-256 of the copy its standing statements come from"`
	Fetched    bool   `json:"fetched,omitempty" doc:"Whether a supplier advisory feed fetched it rather than somebody uploading it"`
	Standing   int    `json:"standing" doc:"Statements of it that stand"`
	SetAside   int    `json:"set_aside" doc:"Statements of it a later copy no longer made, kept and no longer applied"`
	FirstAt    string `json:"first_received_at" doc:"When its first statement was recorded"`
	ChangedAt  string `json:"changed_at" doc:"When an upload last recorded, repeated or set aside one of its statements. The same bytes uploaded again change nothing and leave this alone"`
}

// DocumentsOutput is a page of the documents of one kind a product holds.
type DocumentsOutput struct {
	Body struct {
		Items []DocumentBody `json:"items"`
		Total int            `json:"total"`
	}
}

// documentsInput is a page of the documents one product holds.
type documentsInput struct {
	Product string `path:"product"`
	Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"The number returned"`
	Offset  int    `query:"offset" minimum:"0" doc:"The number skipped"`
}

func registerDocuments(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-vex-documents", Method: http.MethodGet,
		Path:    "/v1/products/{product}/vex-statements",
		Summary: "List uploaded VEX documents",
		Description: "Returns the VEX documents this product holds statements from, one per " +
			"publisher, the most recently changed first: how many of its statements stand, " +
			"how many a later upload set aside, and the file it last arrived as.\n\n" +
			"Statements a trusted upstream publishes are listed with the upstream, not here.",
		Tags: []string{"Ingest"},
	}, core.AnyPerson, "Answers for a product you may see."), documentsOf(in, finding.FromVex))

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-supplier-advisories", Method: http.MethodGet,
		Path:    "/v1/products/{product}/supplier-advisories",
		Summary: "List supplier advisories",
		Description: "Returns the supplier security advisories this product holds statements " +
			"from, one per publisher and advisory name, the most recently changed first: how " +
			"many of its statements stand, how many a later copy set aside, and the file or " +
			"address it last arrived as. An advisory a supplier advisory feed fetched is " +
			"listed beside the uploaded ones and marked `fetched`.",
		Tags: []string{"Ingest"},
	}, core.AnyPerson, "Answers for a product you may see."), documentsOf(in, finding.FromAdvisory))
}

// documentsOf answers a page of the documents of one kind a product holds.
func documentsOf(in core.Deps, source string) func(context.Context, *documentsInput) (*DocumentsOutput, error) {
	return func(ctx context.Context, input *documentsInput) (*DocumentsOutput, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		held, total, err := finding.NewStore(in.DB.DB).Documents(ctx, subject, product.ID,
			source, input.Limit, input.Offset)
		if err != nil {
			return nil, core.Absent(in.Logger, err, "the documents could not be read", core.NoSuchProduct)
		}
		out := &DocumentsOutput{}
		out.Body.Items, out.Body.Total = make([]DocumentBody, 0, len(held)), total
		for _, d := range held {
			out.Body.Items = append(out.Body.Items, DocumentBody{
				Publisher: d.Publisher, Identifier: d.Identifier,
				Document: d.Name, Digest: d.Digest, Fetched: d.Fetched(),
				Standing: d.Standing, SetAside: d.SetAside,
				FirstAt: core.Stamp(d.FirstAt), ChangedAt: core.Stamp(d.ChangedAt),
			})
		}
		return out, nil
	}
}
