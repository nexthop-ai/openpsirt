package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

// Declaring what exists.
//
// A scan may only be filed against something declared, and this is where that
// happens. All three are administrator writes and all three are idempotent:
// declaring what is already there succeeds and changes nothing, because a
// pipeline that has to know whether a branch exists before cutting it is a
// pipeline with a race in it.
func registerDeclaring(api huma.API, d Declaring) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "declare-product", Method: http.MethodPost, Path: "/v1/products",
		Summary: "Create a product",
		Description: "Records a product so scans may be filed against it. Declaring one that " +
			"already exists succeeds without changing anything, so this can run on every build.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Body ProductBody
	}) (*declaredOutput[ProductBody], error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, created, err := store.EnsureProduct(ctx, in.Body.Name, in.Body.DisplayName)
		if err != nil {
			return nil, declineDeclaration(err)
		}
		return answer(created, ProductBody{Name: product.Name, DisplayName: product.DisplayName}), nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "declare-stream", Method: http.MethodPost, Path: "/v1/products/{product}/streams",
		Summary: "Create a branch or tag",
		Description: "Records a line of a product. A branch moves and is rebuilt; a tag never " +
			"changes and is what somebody received.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    StreamBody
	}) (*declaredOutput[StreamBody], error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}

		var parentID *int64
		if in.Body.Parent != "" {
			parent, err := store.StreamByName(ctx, product.ID, in.Body.Parent)
			if err != nil {
				return nil, huma.Error404NotFound(err.Error())
			}
			parentID = &parent.ID
		}

		stream, created, err := store.EnsureStream(ctx, product.ID, in.Body.Name,
			catalog.Kind(in.Body.Kind), parentID)
		if err != nil {
			return nil, declineDeclaration(err)
		}
		return answer(created, StreamBody{
			Name: stream.DisplayName, Kind: string(stream.Kind), Parent: in.Body.Parent,
		}), nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "declare-variant", Method: http.MethodPost,
		Path:    "/v1/products/{product}/variants",
		Summary: "Create a build variant",
		Description: "Records one of the parallel builds of a product — a chip variant, an " +
			"architecture, an operating system. Declared once for the product, not once per " +
			"release: a release is filed against it the first time a scan arrives, so nobody " +
			"restates the list and no release ends up with the name spelled differently.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    VariantBody
	}) (*declaredOutput[VariantBody], error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		store, err := storeFor(d)
		if err != nil {
			return nil, err
		}
		product, err := store.ProductByName(ctx, in.Product)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}

		facing := true
		if in.Body.CustomerFacing != nil {
			facing = *in.Body.CustomerFacing
		}
		variant, created, err := store.EnsureVariant(ctx, product.ID, in.Body.Name, facing)
		if err != nil {
			return nil, declineDeclaration(err)
		}
		return answer(created, VariantBody{Name: variant.DisplayName, CustomerFacing: &variant.CustomerFacing}), nil
	})
}
