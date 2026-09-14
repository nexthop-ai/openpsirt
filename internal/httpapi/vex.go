package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

func registerVEX(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-vex", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/vex",
		Summary: "Generate a VEX document for a build",
		Description: "Returns an OpenVEX document saying what stands about the third-party " +
			"components this build ships: every approved `not applicable` and `already fixed` " +
			"claim, as `not_affected` and `fixed` statements with the justification and the " +
			"reasoning somebody wrote.\n\n" +
			"**Approved claims only**, and a deferral is absent rather than exported as " +
			"anything — silence already reads as affected in this format.\n\n" +
			"**Public findings only.** `undisclosed=true` includes the rest for somebody who " +
			"may read them, which is a preview rather than a thing to publish.\n\n" +
			"Requires a publisher configured for this deployment: a document naming none has " +
			"nobody as its author.",
		Tags: []string{"Findings"},
	}, perProduct, "Answers only what you may see. A grant on one case does not reach it: "+
		"the document is about the whole build rather than about one issue.",
		readRights()...),
		func(ctx context.Context, input *struct {
			Product     string `path:"product"`
			Stream      string `path:"stream"`
			Variant     string `path:"variant"`
			Undisclosed bool   `query:"undisclosed" doc:"Include findings nobody has announced. A preview, not a document to publish"`
		}) (*struct{ Body *vex.Statements }, error) {
			subject, err := reading(ctx)
			if err != nil {
				return nil, err
			}
			if in.DB == nil {
				return nil, noDatabase(in.Logger)
			}
			doc, err := vex.NewStore(in.DB.DB).For(ctx, subject, in.Publisher,
				input.Product, input.Stream, input.Variant, input.Undisclosed)
			switch {
			case errors.Is(err, catalog.ErrNotFound):
				return nil, noSuchProduct()
			case errors.Is(err, access.ErrDenied):
				return nil, noSuchProduct()
			// Asked of the publisher directly. The same question had a
			// wrapper of its own in the package that answers it, so one
			// predicate was spelled two ways in one file — and the wrapper
			// was the half nothing executed.
			case err != nil && !in.Publisher.Stated():
				// A configuration gap rather than a bad request, and named as
				// one: whoever is asking cannot fix it from here, and an
				// operator can.
				return nil, huma.Error409Conflict(err.Error())
			case err != nil:
				return nil, wentWrong(in.Logger, "the document could not be generated", err)
			}
			return &struct{ Body *vex.Statements }{Body: doc}, nil
		})
}
