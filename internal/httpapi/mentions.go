package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// MentionableBody is somebody who could be named in a comment or a
// justification about this product.
type MentionableBody struct {
	Identity string `json:"identity" doc:"What to write after the @"`
	Name     string `json:"name" doc:"What to show while choosing"`
}

func registerMentions(api huma.API, in Ingest) {
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
	}, perProduct, "Asking about undisclosed findings needs private-read or "+
		"private-triage.", readRights()...), func(ctx context.Context, input *struct {
		Product    string `path:"product"`
		Visibility string `query:"visibility" default:"public" enum:"public,private" doc:"Which kind of finding the text is about"`
		Term       string `query:"q" maxLength:"100" doc:"Narrow to names containing this, ignoring capitals. Matched on the identity and on the displayed name"`
		Limit      int    `query:"limit" default:"25" minimum:"1" maximum:"100"`
	}) (*listOutput[MentionableBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		product, err := productNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}

		// Asking who may be told about an undisclosed finding is itself a
		// question about undisclosed findings. Somebody who cannot read them
		// is answered as though the product were not there, which is the same
		// answer every other path gives.
		wanted := access.AsVisibility(input.Visibility)
		if !subject.Reads(wanted, product.ID) {
			return nil, noSuchProduct()
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
