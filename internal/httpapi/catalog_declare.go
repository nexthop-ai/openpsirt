// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// registerDeclaring registers the writes that say what exists.
//
// A scan may only be filed against something declared, and this is where that
// happens. All three are administrator writes and all three are idempotent:
// declaring what is already there succeeds and changes nothing, because a
// pipeline that has to know whether a branch exists before cutting it is a
// pipeline with a race in it.
//
// Declaring what exists leaves no row in the administration trail. Bringing
// back something retired does, because it undoes a retirement the trail
// records, and so does filling in what a tag was cut from, which is a release
// detail the trail records. Each is written in the transaction that makes it.
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
		var out *declaredOutput[ProductBody]
		if err := changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, err := storeFor(d, tx)
			if err != nil {
				return err
			}
			product, did, err := store.EnsureProduct(ctx, in.Body.Name, in.Body.DisplayName)
			if err != nil {
				return declineDeclaration(err)
			}
			if did.Restored {
				if err := noted(ctx, tx, trail.Catalog, product.Name,
					nil, trail.Said("in use", true)); err != nil {
					return notRecorded(d.Logger, err)
				}
			}
			out = answer(did.Changed(), ProductBody{Name: product.Name, DisplayName: product.DisplayName})
			return nil
		}); err != nil {
			return nil, err
		}
		return out, nil
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
		var out *declaredOutput[StreamBody]
		if err := changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, err := storeFor(d, tx)
			if err != nil {
				return err
			}
			product, err := store.ProductByName(ctx, in.Product)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}

			var parent *catalog.Stream
			var parentID *int64
			if in.Body.Parent != "" {
				parent, err = store.StreamByName(ctx, product.ID, in.Body.Parent)
				if err != nil {
					return undeclared(d.Logger, err, "the release it was cut from could not be looked up")
				}
				parentID = &parent.ID
			}

			stream, did, err := store.EnsureStream(ctx, product.ID, in.Body.Name,
				catalog.Kind(in.Body.Kind), parentID)
			if err != nil {
				return declineDeclaration(err)
			}
			if did.Restored {
				if err := noted(ctx, tx, trail.Catalog, product.Name+" "+stream.Name,
					nil, trail.Said("in use", true)); err != nil {
					return notRecorded(d.Logger, err)
				}
			}
			if did.FilledIn {
				if err := noted(ctx, tx, trail.Release, product.Name+" "+stream.Name+" cut from",
					nil, trail.Said(parent.Name, true)); err != nil {
					return notRecorded(d.Logger, err)
				}
			}
			out = answer(did.Changed(), StreamBody{
				Name: stream.DisplayName, Kind: string(stream.Kind), Parent: in.Body.Parent,
			})
			return nil
		}); err != nil {
			return nil, err
		}
		return out, nil
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
		facing := true
		if in.Body.CustomerFacing != nil {
			facing = *in.Body.CustomerFacing
		}
		var out *declaredOutput[VariantBody]
		if err := changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, err := storeFor(d, tx)
			if err != nil {
				return err
			}
			product, err := store.ProductByName(ctx, in.Product)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			variant, did, err := store.EnsureVariant(ctx, product.ID, in.Body.Name, facing)
			if err != nil {
				return declineDeclaration(err)
			}
			if did.Restored {
				if err := noted(ctx, tx, trail.Catalog, product.Name+" "+variant.Name,
					nil, trail.Said("in use", true)); err != nil {
					return notRecorded(d.Logger, err)
				}
			}
			out = answer(did.Changed(), VariantBody{Name: variant.DisplayName, CustomerFacing: &variant.CustomerFacing})
			return nil
		}); err != nil {
			return nil, err
		}
		return out, nil
	})
}
