package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// UpwardBody is one node of the tree somebody's own work hangs from.
type UpwardBody struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Depth     int    `json:"depth" doc:"How far below the build's root it sits, so the tree is drawn by indenting"`
	Findings  int    `json:"findings" doc:"Your own open issues on this component itself"`
	Beneath   int    `json:"beneath" doc:"Your own open issues at or under it along these chains. Never how much the build holds there"`
	Placed    bool   `json:"placed" doc:"False for a component the inventory put nowhere. Those sit at the end with no chain"`
}

// OursOutput is the tree, seen upward.
type OursOutput struct {
	Body struct {
		Items []UpwardBody `json:"items"`
		// Complete says the tree covers everything of theirs here. Said rather
		// than left to be noticed: where it is false the counts under-report.
		Complete bool `json:"complete" doc:"Whether this covers everything you hold in this build. False where you hold work on more components than this assembles, and then the counts under-report"`
	}
}

// registerUpward is the tree seen upward, for somebody narrowed to their own
// work.
func registerUpward(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-my-components", Method: http.MethodGet,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/components/mine",
		Summary: "Show the chains your own findings sit on",
		Description: "The build's dependency graph, seen upward from your own work: from each " +
			"component you hold a finding on, up to the build's root.\n\n" +
			"**This is what the tree is for somebody who holds no reading on the product.** " +
			"Descended from the root, that tree is the inventory of what the product " +
			"contains — the breadth they were not granted — so it cannot be offered with rows " +
			"hidden: a container's count would still say how much sits under it. The chain " +
			"upward is the part that makes a finding judgeable, because it says what pulled " +
			"the thing in, and every node on it sits above something already granted.\n\n" +
			"**The counts are yours.** A node says how much of your own work hangs beneath it " +
			"along these chains, never how much the build holds there.\n\n" +
			"Rows come back in the order they are drawn, parents before children, the fullest " +
			"branch first. A component the inventory placed nowhere has no chain and sits at " +
			"the end.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers what you hold, whether or not you read the product."),
		func(ctx context.Context, input *struct {
			Product string `path:"product"`
			Stream  string `path:"stream"`
			Variant string `path:"variant"`
		}) (*OursOutput, error) {
			subject, err := reading(ctx)
			if err != nil {
				return nil, err
			}
			names := catalog.NewStore(in.DB.DB)
			// Located without the visibility check, because the whole point is
			// somebody who may not see the product — and then answered as a
			// product that does not exist unless they hold work here. A reader
			// keeps the ordinary answer: for them an empty tree means they
			// hold nothing, which is not the same sentence.
			named, err := names.Locate(ctx, input.Product, input.Stream, input.Variant)
			if err != nil {
				return nil, noSuchProduct()
			}
			target, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
			if err != nil {
				if subject.Sees(named.ProductID) {
					return nil, nothingScannedThere()
				}
				return nil, noSuchProduct()
			}
			rows, complete, err := graph.NewStore(in.DB.DB).Ours(ctx, subject, target.ID)
			if err != nil {
				return nil, wentWrong(in.Logger, "your own work here could not be read", err)
			}
			if len(rows) == 0 && !subject.Sees(named.ProductID) {
				return nil, noSuchProduct()
			}
			out := &OursOutput{}
			out.Body.Complete = complete
			out.Body.Items = make([]UpwardBody, 0, len(rows))
			for _, row := range rows {
				out.Body.Items = append(out.Body.Items, UpwardBody{
					Component: row.Component, Version: row.Version, Depth: row.Depth,
					Findings: row.Findings, Beneath: row.Beneath, Placed: row.Placed,
				})
			}
			return out, nil
		})
}
