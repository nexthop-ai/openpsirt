// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

// MentionableBody is somebody who could be named in a comment or a
// justification about this product.
type MentionableBody struct {
	Identity string `json:"identity" doc:"The name written after the @"`
	Name     string `json:"name" doc:"The label shown while choosing"`
}

func registerMentions(api huma.API, in Deps) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-mentionable", Method: http.MethodGet,
		Path:    "/v1/products/{product}/mentionable",
		Summary: "List who may be mentioned here",
		Description: "Returns the people who can already read findings of this visibility in " +
			"this product, so an editor can offer them.\n\n" +
			"Only people who can already see the thing. An autocomplete listing everybody " +
			"teaches somebody to name a colleague who then cannot open what they were called " +
			"to — and on an undisclosed finding, the mention itself says a finding exists, " +
			"which is the disclosure the visibility rule prevents.\n\n" +
			"`visibility` says which kind of finding the text is about. Asking about " +
			"undisclosed findings requires being able to read them.",
		Tags: []string{"Triage"},
	}, perProduct, "Asking about disclosed findings, the default, needs public-read or "+
		"public-triage; about undisclosed findings, private-read or private-triage.",
		readRights()...), func(ctx context.Context, input *struct {
		Product    string `path:"product"`
		Visibility string `query:"visibility" default:"public" enum:"public,private" doc:"The kind of finding the text is about"`
		Term       string `query:"q" maxLength:"100" doc:"Narrow to names containing this, ignoring capitals. Matched on the identity and on the displayed name"`
		Limit      int    `query:"limit" default:"25" minimum:"1" maximum:"100"`
	}) (*listOutput[MentionableBody], error) {
		subject, product, wanted, err := readersHere(ctx, in, input.Product, input.Visibility)
		if err != nil {
			return nil, err
		}

		found, err := access.NewStore(in.DB.DB).WhoCanRead(ctx, subject, product.ID, wanted, input.Term, input.Limit)
		if err != nil {
			return nil, wentWrong(in.Logger, "who may be mentioned could not be read", err)
		}

		out := &listOutput[MentionableBody]{}
		out.Body.Items = make([]MentionableBody, 0, len(found))
		for _, person := range found {
			out.Body.Items = append(out.Body.Items, MentionableBody{
				Identity: person.Identity, Name: person.Name,
			})
		}
		return out, nil
	})
}

// readersHere resolves who is asking about the readers of a product, the
// product, and the visibility asked about, for the pickers that offer people
// who can already read what they would be named on or handed.
//
// A request about who may read undisclosed work is itself about undisclosed
// work. Somebody who cannot read it is answered as though the product were not
// there, which is the answer every other path gives.
func readersHere(ctx context.Context, in Deps, product, visibility string) (
	access.Subject, *catalog.Product, access.Visibility, error) {

	subject, err := reading(ctx)
	if err != nil {
		return access.Subject{}, nil, "", err
	}
	if in.DB == nil {
		return access.Subject{}, nil, "", noDatabase(in.logger())
	}
	named, err := productNamedVisibly(ctx, in, subject, product)
	if err != nil {
		return access.Subject{}, nil, "", err
	}
	wanted := access.AsVisibility(visibility)
	if !subject.Reads(wanted, named.ID) {
		return access.Subject{}, nil, "", noSuchProduct()
	}
	return subject, named, wanted, nil
}
