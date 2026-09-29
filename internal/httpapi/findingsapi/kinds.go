// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// PackageKindBody is one kind of package open findings sit at.
type PackageKindBody struct {
	Kind string `json:"kind" doc:"The package type as the package identifier spells it, such as deb, golang or pypi. What the findings list's ecosystem filter takes"`
	Open int    `json:"open" doc:"The number of findings list rows open at packages of this kind: one per issue at a source package and version, however many builds and binaries hold it"`
}

// PackageKindsOutput is the kinds of package present in a selection.
type PackageKindsOutput struct {
	Body struct {
		Items []PackageKindBody `json:"items"`
	}
}

const kindsSaid = "Counted over every open finding in the selection you may read. The " +
	"findings list's other filters and the triage line do not narrow it. A kind present only " +
	"on findings you may not read is absent. A package identifier the ecosystem filter cannot " +
	"find by a kind is not counted, and neither is a component with none. Ordered by the " +
	"count, largest first."

// registerKinds is the package kinds present, per product and across products.
func registerKinds(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-package-kinds", Method: http.MethodGet,
		Path:    "/v1/products/{product}/findings/package-kinds",
		Summary: "List package kinds with open findings",
		Description: "Returns each kind of package that open findings in the product sit at, " +
			"with how many.\n\n" + kindsSaid + "\n\n" +
			"`stream` and `variant` are optional and independent, as they are on the findings " +
			"list.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `query:"stream" doc:"Limit to one branch or tag. Left out, every one under the product"`
		Variant string `query:"variant" doc:"Limit to one variant. Left out, every one under the product, and independent of the branch"`
	}) (*PackageKindsOutput, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		scope, err := core.Scoped(ctx, in, subject, core.ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		})
		if err != nil {
			return nil, err
		}
		kinds, err := finding.NewStore(in.DB.DB).PackageKinds(ctx, subject, scope)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "cannot read what is open")
		}
		return kindsOutput(kinds), nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-package-kinds-anywhere", Method: http.MethodGet,
		Path:    "/v1/findings/package-kinds",
		Summary: "List package kinds with open findings across every product",
		Description: "Returns each kind of package that open findings sit at, across every " +
			"product you may see, with how many. The same issue at the same package in two products " +
			"counts in each, as it is two rows on the findings list across products.\n\n" + kindsSaid,
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, _ *struct{}) (*PackageKindsOutput, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, core.NoDatabase(in.Logger)
		}
		kinds, err := finding.NewStore(in.DB.DB).PackageKindsAnywhere(ctx, subject)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "cannot read what is open")
		}
		return kindsOutput(kinds), nil
	})
}

func kindsOutput(kinds []finding.PackageKind) *PackageKindsOutput {
	out := &PackageKindsOutput{}
	out.Body.Items = make([]PackageKindBody, 0, len(kinds))
	for _, kind := range kinds {
		out.Body.Items = append(out.Body.Items, PackageKindBody{Kind: kind.Kind, Open: kind.Open})
	}
	return out
}
