// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// InventoryChangeBody is one name an upload moved.
type InventoryChangeBody struct {
	Name string `json:"name" doc:"The component name, as the document wrote it"`
	// Change is the word the count on the receipt uses for it, so a caller
	// reading both is reading one answer.
	Change string `json:"change" enum:"added,removed,changed" doc:"What the upload did to this name"`
	// Before and After carry every version of the name on each side. A
	// vendored tree ships one name at several versions at once, and which of
	// them moved is the answer somebody opened this for.
	Before []string `json:"before,omitempty" doc:"The versions the build held before this upload. Empty where the name arrived"`
	After  []string `json:"after,omitempty" doc:"The versions it holds from this upload. Empty where the name went"`
}

// ListedInventoryChanges is what an upload moved, as the operation answers it.
//
// Named so that a test can decode the answer rather than restate its shape,
// which is a second copy of the fields to keep in step with these.
type ListedInventoryChanges = listOutput[InventoryChangeBody]

// registerInventoryChanges answers which names one upload moved.
//
// The counts on a receipt say how much moved and this says what. They are one
// comparison read twice: an alert about a build that changed sharply is an
// alarm pointing at nothing without somewhere to go and look.
func registerInventoryChanges(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-inventory-changes", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/scans/{scan}/changes",
		Summary: "List what an upload changed about a build's inventory",
		Description: "Returns the component names this upload added, removed and moved to " +
			"different versions, against the upload read before it. Removals first, then " +
			"arrivals, then the names that moved version.\n\n" +
			"Counted by name rather than by component, so a dependency upgraded is one name " +
			"that moved rather than one arrival and one departure. A name the build ships at " +
			"several versions at once carries all of them on each side.\n\n" +
			"Empty for the first upload read for a build, which is the first picture of it " +
			"rather than a change to one, and for an upload nothing has read yet.",
		Tags: []string{"Scans"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Scan    int64  `path:"scan" doc:"The upload, as a receipt names it"`
		Change  string `query:"change" enum:"added,removed,changed" doc:"One kind of change alone"`
		Limit   int    `query:"limit" default:"200" minimum:"1" maximum:"500" doc:"The number returned"`
		Offset  int    `query:"offset" minimum:"0" doc:"The number skipped"`
	}) (*ListedInventoryChanges, error) {
		subject, err := requester(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}

		// Resolved and authorized together, so a build somebody may not reach
		// reads as one that was never declared.
		names := catalog.NewStore(in.DB.DB)
		named, err := names.LocateVisible(ctx, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, undeclared(in.Logger, err, "that build could not be looked up")
		}
		if subject.Kind == access.Pipeline &&
			!subject.MaySend(named.ProductID, named.StreamID, named.VariantID) {
			return nil, huma.Error403Forbidden("not authorized")
		}

		out := &ListedInventoryChanges{}
		out.Body.Items = []InventoryChangeBody{}
		target, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
		if err != nil {
			// Declared, and nothing has ever been filed against it.
			return out, nil
		}

		changes, total, err := graph.NewStore(in.DB.DB).Changes(ctx, subject, target.ID,
			input.Scan, graph.ChangeKind(input.Change), input.Limit, input.Offset)
		switch {
		case errors.Is(err, access.ErrDenied):
			return nil, nothingScannedThere()
		// The store also refuses a kind of change nobody has, which the
		// schema has already turned away by the time a request reaches here.
		case err != nil:
			return nil, wentWrong(in.Logger,
				"what the upload changed could not be read", err)
		}

		out.Body.Total = total
		for _, change := range changes {
			out.Body.Items = append(out.Body.Items, InventoryChangeBody{
				Name: change.Name, Change: string(change.Kind),
				Before: change.Before, After: change.After,
			})
		}
		return out, nil
	})
}
