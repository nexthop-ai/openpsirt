package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// Reading what exists.
//
// Every one answers a list narrowed to what the reader may see, with what
// each row holds beside it: a catalog that answers only names makes somebody
// open every row to find out whether there is anything behind it, which is
// the question the list exists to answer.
func registerCatalogReading(api huma.API, d Declaring) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-products", Method: http.MethodGet, Path: "/v1/products",
		Summary: "List products",
		Description: "Lists the products declared here, with what each one holds.\n\n" +
			"A scan may only be filed against something declared, so this is the first question " +
			"to ask after an upload is refused for naming something unknown.",
		Tags: []string{"Catalog"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, _ *struct{}) (*listOutput[ProductBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		rows, err := store.Products(ctx, subject)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot list products", err)
		}

		ids := make([]int64, 0, len(rows))
		for _, row := range rows {
			ids = append(ids, row.ID)
		}
		shapes, err := store.Shapes(ctx, subject, ids)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot count what the products hold", err)
		}
		open, err := d.Findings().OpenBy(ctx, subject, finding.Scope{}, finding.ByProduct)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot count what is open", err)
		}
		// When each product was last scanned comes from the same answer the
		// home page reads, rather than a second query that could disagree
		// with it about which build counts.
		seen, err := lastScans(ctx, d.Scans(), subject)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot read when these were last scanned", err)
		}

		out := &listOutput[ProductBody]{}
		out.Body.Items = make([]ProductBody, 0, len(rows))
		for _, row := range rows {
			shape := shapes[row.ID]
			out.Body.Items = append(out.Body.Items, ProductBody{
				Name: row.Name, DisplayName: row.DisplayName,
				Branches: shape.Branches, Tags: shape.Tags, Variants: shape.Variants,
				Open:        open[row.ID],
				LastScanAt:  seen[row.Name],
				TriageFloor: stated(row.TriageFloor),
				EndOfLife:   onDate(row.EOLOn),
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-streams", Method: http.MethodGet, Path: "/v1/products/{product}/streams",
		Summary: "List a product's branches and tags",
		Description: "Every stream declared under this product, with how many variants each " +
			"has and how much is open in it.\n\n" +
			"A stream is a branch or a tag: a branch is scanned nightly and superseded, a " +
			"tag is immutable and kept. Both are declared before a scan may name one, so a " +
			"typo in a pipeline is refused rather than quietly creating a line with findings " +
			"and reports of its own.\n\n" +
			"A stream past its end-of-life date is listed and says so. It stops being a " +
			"place a fix may be declared for, and what is open against it is still counted.",
		Tags: []string{"Catalog"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, in *struct {
		Product string `path:"product"`
	}) (*listOutput[StreamBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.VisibleProduct(ctx, subject, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		rows, err := store.Streams(ctx, subject, product.ID)
		if err != nil {
			return nil, refused(d.Logger, err, "cannot list streams")
		}
		open, err := d.Findings().OpenBy(ctx, subject, finding.Scope{ProductID: &product.ID}, finding.ByStream)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot count what is open", err)
		}
		seen, err := lastScansIn(ctx, d.Scans(), subject, product.ID, func(c ingest.Coverage) string {
			return c.Stream
		})
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot read when these were last scanned", err)
		}

		// The product's date, read once, so a release that has not stated one
		// shows what actually applies to it rather than a blank that reads as
		// "supported for ever".
		// What each tag was cut from, by name. The rows carry the parent as an
		// identifier and this list never resolved it, so the column reporting
		// it was empty whatever the data said — which reads as "none of these
		// was cut from anything" and is what release readiness depends on.
		named := make(map[int64]string, len(rows))
		for _, row := range rows {
			named[row.ID] = row.Name
		}

		out := &listOutput[StreamBody]{}
		out.Body.Items = make([]StreamBody, 0, len(rows))
		for _, row := range rows {
			body := StreamBody{
				Name: row.Name, Kind: string(row.Kind),
				Open: open[row.ID], LastScanAt: seen[row.Name],
			}
			if row.ParentID != nil {
				body.Parent = named[*row.ParentID]
			}
			body.ReleasedOn = onDate(row.ReleasedOn)
			switch {
			case row.EOLOn != nil:
				body.EndOfLife = onDate(row.EOLOn)
			case product.EOLOn != nil:
				body.EndOfLife, body.EndOfLifeInherited = onDate(product.EOLOn), true
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-variants", Method: http.MethodGet,
		Path:    "/v1/products/{product}/variants",
		Summary: "List a product's build variants",
		Description: "Every variant declared under this product, with how much is open in " +
			"each.\n\n" +
			"A variant is a way one release is built — a hardware platform, a flavor — and " +
			"it is independent of the branch: every stream may be built as any of them. One " +
			"variant is the ordinary case, and the interface hides the dimension where there " +
			"is only one.\n\n" +
			"Each says whether it is customer-facing, which feeds how urgent a finding in it " +
			"is, and defaults to customer-facing where nobody has said.",
		Tags: []string{"Catalog"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, in *struct {
		Product string `path:"product"`
	}) (*listOutput[VariantBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.VisibleProduct(ctx, subject, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		rows, err := store.Variants(ctx, subject, product.ID)
		if err != nil {
			return nil, refused(d.Logger, err, "cannot list variants")
		}
		open, err := d.Findings().OpenBy(ctx, subject, finding.Scope{ProductID: &product.ID}, finding.ByVariant)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot count what is open", err)
		}
		list := variantList(rows)
		for i := range list.Body.Items {
			list.Body.Items[i].Open = open[rows[i].ID]
		}
		return list, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-release-variants", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants",
		Summary: "List the variants a release was built as",
		Description: "Lists the variants one release was actually built as — a subset of what " +
			"the product declares.\n\n" +
			"A release predating a variant has never been filed against it and does not list " +
			"it, which is what keeps something introduced later from appearing to have shipped " +
			"years ago.",
		Tags: []string{"Catalog"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
	}) (*listOutput[VariantBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		_, stream, err := store.VisibleStream(ctx, subject, in.Product, in.Stream)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		rows, err := store.BuiltAs(ctx, subject, stream.ID)
		if err != nil {
			return nil, refused(d.Logger, err, "cannot list what a release is built as")
		}
		// Counted within this stream rather than across the product. The list
		// of what a release was built as carried no count at all, so every
		// screen drawing the column drew zeroes — including for a variant
		// holding twenty-five, which reads as a clean build rather than as a
		// number nobody filled in.
		productID := stream.ProductID
		open, err := d.Findings().OpenBy(ctx, subject,
			finding.Scope{ProductID: &productID, StreamID: &stream.ID}, finding.ByVariant)
		if err != nil {
			return nil, wentWrong(d.Logger, "cannot count what is open", err)
		}
		list := variantList(rows)
		for i := range list.Body.Items {
			list.Body.Items[i].Open = open[rows[i].ID]
		}
		return list, nil
	})
}
