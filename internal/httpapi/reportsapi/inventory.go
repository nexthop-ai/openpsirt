// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
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
type ListedInventoryChanges = core.ListOutput[InventoryChangeBody]

// registerInventoryChanges answers which names one upload moved.
//
// The counts on a receipt say how much moved and this says what. They are one
// comparison read twice: an alert about a build that changed sharply is an
// alarm pointing at nothing without somewhere to go and look.
func registerInventoryChanges(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
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
	}, core.AnySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Scan    int64  `path:"scan" doc:"The upload, as a receipt names it"`
		Change  string `query:"change" enum:"added,removed,changed" doc:"One kind of change alone"`
		Limit   int    `query:"limit" default:"200" minimum:"1" maximum:"500" doc:"The number returned"`
		Offset  int    `query:"offset" minimum:"0" doc:"The number skipped"`
	}) (*ListedInventoryChanges, error) {
		subject, err := core.Requester(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, core.NoDatabase(in.Logger)
		}

		// Resolved and authorized together, so a build somebody may not reach
		// reads as one that was never declared.
		names := catalog.NewStore(in.DB.DB)
		named, err := names.LocateVisible(ctx, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, core.Undeclared(in.Logger, err, "that build could not be looked up")
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
			return nil, core.NothingScannedThere()
		// The store also refuses a kind of change nobody has, which the
		// schema has already turned away by the time a request reaches here.
		case err != nil:
			return nil, core.WentWrong(in.Logger,
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

// InventoryDifferenceBody is one name two builds hold differently.
type InventoryDifferenceBody struct {
	Name   string   `json:"name" doc:"The component name, as a document wrote it"`
	Change string   `json:"change" enum:"added,removed,changed" doc:"How the later build differs from the earlier one on this name"`
	Before []string `json:"before,omitempty" doc:"The versions the earlier build holds. Empty where only the later build holds the name"`
	After  []string `json:"after,omitempty" doc:"The versions the later build holds. Empty where only the earlier build holds the name"`
}

// ListedInventoryDifferences is how two builds' inventories differ, as the
// operation answers it.
type ListedInventoryDifferences = core.ListOutput[InventoryDifferenceBody]

// differences resolves the two builds and works out how their inventories
// differ.
func (pair TwoBuilds) differences(ctx context.Context, in core.Deps, subject access.Subject,
	product string, only string, limit, offset int) ([]graph.Change, int, error) {

	from, to, err := pair.targets(ctx, in, subject, product)
	if err != nil {
		return nil, 0, err
	}
	changes, total, err := graph.NewStore(in.DB.DB).Between(ctx, subject, from, to,
		graph.ChangeKind(only), limit, offset)
	switch {
	case errors.Is(err, access.ErrDenied):
		return nil, 0, core.NothingScannedThere()
	case errors.Is(err, graph.ErrNoInventory):
		return nil, 0, huma.Error404NotFound("no inventory has been read for one of those builds")
	case err != nil:
		return nil, 0, core.WentWrong(in.Logger, "how the two builds differ could not be read", err)
	}
	return changes, total, nil
}

// registerInventoryComparison answers which names any two builds differ on.
//
// An upload's own listing compares a build with itself a moment earlier. This
// compares two builds: two releases, two platforms of one release, or a tag and
// the branch it was cut from.
func registerInventoryComparison(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "compare-inventories", Method: http.MethodGet,
		Path:    "/v1/products/{product}/comparison/inventory",
		Summary: "Compare the inventories of two builds",
		Description: "Returns the component names the later build added, removed and holds at " +
			"different versions, against the earlier build. Removals first, then " +
			"arrivals, then the names at different versions.\n\n" +
			"Any two builds of one product, across streams and variants. Each is compared " +
			"as its most recent inventory stands.\n\n" +
			"Counted by name, as the listing of one upload is. A name either build holds " +
			"at several versions carries all of them on each side.\n\n" +
			"Answers 404 where either build has no inventory read yet.",
		Tags: []string{"Scans"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		TwoBuilds
		Change string `query:"change" enum:"added,removed,changed" doc:"One kind of change alone"`
		Limit  int    `query:"limit" default:"200" minimum:"1" maximum:"500" doc:"The number returned"`
		Offset int    `query:"offset" minimum:"0" doc:"The number skipped"`
	}) (*ListedInventoryDifferences, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		changes, total, err := input.differences(ctx, in, subject, input.Product,
			input.Change, input.Limit, input.Offset)
		if err != nil {
			return nil, err
		}
		out := &ListedInventoryDifferences{}
		out.Body.Total = total
		out.Body.Items = make([]InventoryDifferenceBody, 0, len(changes))
		for _, change := range changes {
			out.Body.Items = append(out.Body.Items, InventoryDifferenceBody{
				Name: change.Name, Change: string(change.Kind),
				Before: change.Before, After: change.After,
			})
		}
		return out, nil
	})
}

// registerInventoryComparisonExport writes out which names two builds differ
// on, whole rather than a page of them.
func registerInventoryComparisonExport(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "export-inventory-comparison", Method: http.MethodGet,
		Path:    "/v1/products/{product}/comparison/inventory.{format}",
		Summary: "Export an inventory comparison of two builds",
		Description: "Every name the inventory comparison lists, as a file, in the same order.\n\n" +
			"One row per name. A name held at several versions has them joined with `; ` " +
			"in the before and after columns.\n\n" +
			"Answers 404 where either build has no inventory read yet.",
		Tags: []string{"Scans"},
	}, core.AnyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Format  string `path:"format" enum:"csv,json"`
		TwoBuilds
		Change string `query:"change" enum:"added,removed,changed" doc:"One kind of change alone"`
	}) (*huma.StreamResponse, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		// Worked out whole before the response starts, so a build out of reach
		// or without an inventory is refused with a status rather than a file
		// cut short. It is bounded by what two builds hold now.
		changes, _, err := input.differences(ctx, in, subject, input.Product, input.Change, 0, 0)
		if err != nil {
			return nil, err
		}
		out := core.Exporting{
			What: "inventory comparison of two builds",
			About: []core.Stated{
				{Label: "earlier build", Value: input.From + " (" + input.FromVariant + ")"},
				{Label: "later build", Value: input.To + " (" + input.ToVariant + ")"},
				{Label: "change", Value: input.Change},
			},
			Header: []string{"change", "name", "before", "after"},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				if offset > 0 {
					return nil, nil
				}
				rows := make([][]string, 0, len(changes))
				for _, change := range changes {
					rows = append(rows, []string{
						string(change.Kind), change.Name,
						strings.Join(change.Before, "; "), strings.Join(change.After, "; "),
					})
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			core.WriteExport(writer, input.Format, "inventory-comparison-"+core.DownloadName(input.Product), out)
		}}, nil
	})
}
