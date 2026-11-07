// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// GroupedComponentBody names the one component a group holds, in the parts a
// narrowing beneath it takes.
type GroupedComponentBody struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty" doc:"Send it back as beneath_ecosystem"`
	Namespace string `json:"namespace,omitempty" doc:"Send it back as beneath_namespace"`
}

// GroupBody is one row of a build's components listed by repository,
// ecosystem or package.
type GroupBody struct {
	Key            string                `json:"key" doc:"The repository's or package's identifier with version and qualifiers cut, such as pkg:github/sonic-net/sonic-swss, or the ecosystem: the identifier's type, or none for components with no identifier"`
	Versions       []string              `json:"versions" doc:"What the build ships of it now, as its identifiers state it: a repository's commits, a package's versions. At most five"`
	Components     int                   `json:"components" doc:"How many of the build's components it holds now"`
	Open           int                   `json:"open" doc:"Issues at components open in the build: at its components and, for a repository, everything beneath them"`
	Fixed          int                   `json:"fixed" doc:"Issues at components that left by a fix and are open nowhere in the group now"`
	OpenBySeverity map[string]int        `json:"open_by_severity" doc:"Open, split by severity"`
	Component      *GroupedComponentBody `json:"component,omitempty" doc:"The one component the group holds, where it holds exactly one"`
}

func registerGrouped(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-component-groups", Method: http.MethodGet,
		Path:    "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/component-groups",
		Summary: "List a build's components by repository or ecosystem",
		Description: "The build's components grouped instead of drawn as a tree, most open first.\n\n" +
			"`by=repository` is one row per source repository a package identifier of type github " +
			"names, such as pkg:github/sonic-net/sonic-swss, with the commits the build ships; its " +
			"counts cover its components and everything beneath them, however the inventory " +
			"places the repository. `by=ecosystem` is one row per identifier type, counting what " +
			"is at its own components; with `ecosystem` it is one row per package of that type.\n\n" +
			"Each count is of an issue at a component, as the trend and the burndown count. " +
			"Grouping is presentation: nothing is decided or counted per group. Reading the " +
			"product is required; somebody holding no reading there is answered as though nothing " +
			"was scanned.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product     string       `path:"product"`
		BranchOrTag string       `path:"branch_or_tag"`
		Variant     string       `path:"variant"`
		By          core.GroupBy `query:"by" required:"true" doc:"repository or ecosystem"`
		Ecosystem   string       `query:"ecosystem" maxLength:"64" doc:"With by=ecosystem, list the packages of this ecosystem instead of the ecosystems"`
	}) (*core.ListOutput[GroupBody], error) {
		in := core.Of(ctx, in)
		subject, _, build, err := core.BrowsingIn(ctx, in, input.Product, input.BranchOrTag, input.Variant)
		if err != nil {
			return nil, err
		}
		if input.Ecosystem != "" && input.By != core.GroupBy(finding.ByEcosystem) {
			return nil, huma.Error422UnprocessableEntity("ecosystem lists the packages of one ecosystem, so it needs by=ecosystem")
		}
		groups, err := finding.NewStore(in.DB.DB).Grouped(ctx, subject, build, finding.GroupBy(input.By), input.Ecosystem)
		switch {
		case errors.Is(err, access.ErrDenied):
			return nil, core.NothingScannedThere()
		case err != nil:
			return nil, core.WentWrong(in.Logger, "the build's components could not be grouped", err)
		}
		out := &core.ListOutput[GroupBody]{}
		out.Body.Items = make([]GroupBody, 0, len(groups))
		for _, g := range groups {
			row := GroupBody{
				Key: g.Key, Versions: g.Versions, Components: g.Components, Open: g.Open, Fixed: g.Fixed,
				OpenBySeverity: g.OpenBySeverity,
			}
			if row.Versions == nil {
				row.Versions = []string{}
			}
			if g.One != nil {
				row.Component = &GroupedComponentBody{
					Name: g.One.Name, Version: g.One.Version, Ecosystem: g.One.Type, Namespace: g.One.Namespace,
				}
			}
			out.Body.Items = append(out.Body.Items, row)
		}
		return out, nil
	})
}
