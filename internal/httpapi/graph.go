// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// NeighborBody is one component next to another.
type NeighborBody struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Findings  int    `json:"findings" doc:"Open findings against this component itself"`
	Beneath   int    `json:"beneath" doc:"Open findings in everything under it, including on it. A container holds none of its own, so this is the number that says whether a branch is worth opening"`
	// BeneathBy is that number by how the issues were rated. Five thousand
	// beneath a node says nothing about whether any of it matters, which is
	// what somebody deciding where to descend is actually asking. The bands
	// sum to `beneath`, because an issue has one rating.
	BeneathBy map[string]int `json:"beneath_by_severity,omitempty" doc:"The same number by how the issues were rated, which is what says whether a branch is worth opening. 'unrated' is what nobody scored, and the bands sum to beneath"`
	Children  int            `json:"children" doc:"The number of components it pulls in. Zero means nothing to open"`
	// Ecosystem is what tells two components of one name and one version
	// apart. The endpoint that answers about one refuses a name the build
	// holds twice and says to send this; a list that did not carry it left
	// nothing able to.
	Ecosystem string `json:"ecosystem,omitempty" doc:"The kind of package this is, as its identifier spells it. Send it back where a build holds one name at one version as two components"`
	Namespace string `json:"namespace,omitempty" doc:"The namespace its package identifier names, where it names one. Send it back where a build holds one name at one version in one ecosystem as two components"`
}

// RootsBody is the build's own component and what it pulls in directly.
type RootsBody struct {
	Root  *NeighborBody  `json:"root,omitempty" doc:"The build itself, which everything below descends from. Absent where the inventory named no root of its own"`
	Items []NeighborBody `json:"items"`
	// Components and Edges say how much there is, which is what a reader needs
	// before deciding whether to browse or to search. Two numbers rather than
	// one because they answer different questions: how much was inventoried,
	// and how much of it was placed.
	Components int `json:"components" doc:"The number of components this build holds"`
	Edges      int `json:"edges" doc:"The number of edges placing them"`
	// Searching is the term somebody typed when Items would be thousands
	// long, and it comes back with the answer.
	Term string `json:"term,omitempty" doc:"The search this answers, where one was asked"`
}

type rootsOutput struct {
	Body RootsBody
}

// AroundBody is what sits above and below one component.
type AroundBody struct {
	Above []NeighborBody `json:"above" doc:"The consumers that pull this in — usually short, and the direction people use"`
	Below []NeighborBody `json:"below" doc:"The components it pulls in, downward"`
}

func registerGraph(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-top-level-components", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/components",
		Summary: "List what a build pulls in directly",
		Description: "Returns the build's own component and what it depends on, most findings " +
			"first. The root is named separately from the list because it is what the list " +
			"hangs from rather than a member of it.\n\n" +
			"The starting point for walking the graph. A full render is not offered and would " +
			"not be useful: a real image holds thousands of components and tens of thousands of " +
			"edges, which neither draws nor reads. Ask for one step at a time.\n\n" +
			"Every entry carries how many findings are open against it and how many components " +
			"it pulls in, so descending follows something rather than being exploration.\n\n" +
			"With `q` it searches instead: components anywhere in the build whose name contains " +
			"that text, most findings first and no root. Nobody finds anything in a graph this " +
			"size by opening nodes — a real image holds eight thousand components under a root " +
			"with five thousand children — so searching is the way in, and browsing is for " +
			"answering \"what else is under this\" once you are already somewhere.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Term    string `query:"q" maxLength:"200" doc:"Find components anywhere in this build whose name contains this, instead of listing what the build pulls in directly"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"The number of matches returned. Only read when searching"`
	}) (*rootsOutput, error) {
		subject, target, err := browsing(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		store := graph.NewStore(in.DB.DB)

		// A refusal from the store is the answer a build nobody declared
		// gets, not a fault. Falling through to the fault answer, this route
		// says 500 where a stranger gets 404 — and the pair says which builds
		// exist, one name at a time. A case collaborator is the reach that
		// meets it: they hold nothing on the product and may open exactly one
		// finding.
		components, edges, err := store.Counts(ctx, subject, target)
		switch {
		case errors.Is(err, access.ErrDenied):
			return nil, nothingScannedThere()
		case err != nil:
			return nil, wentWrong(in.Logger, "the build's contents could not be counted", err)
		}
		out := &rootsOutput{}
		out.Body.Components = components
		out.Body.Edges = edges

		// A search answers with matches and no root. The request is for a set
		// of components rather than a position, and naming a root
		// beside them would invite drawing them as though they hung off it.
		if strings.TrimSpace(input.Term) != "" {
			found, err := store.Search(ctx, subject, target, input.Term, input.Limit)
			switch {
			case errors.Is(err, access.ErrDenied):
				return nil, nothingScannedThere()
			case err != nil:
				return nil, wentWrong(in.Logger, "the build could not be searched", err)
			}
			out.Body.Term = input.Term
			out.Body.Items = neighbors(found)
			return out, nil
		}

		root, roots, err := store.Roots(ctx, subject, target)
		switch {
		case errors.Is(err, access.ErrDenied):
			return nil, nothingScannedThere()
		case err != nil:
			return nil, wentWrong(in.Logger, "the build's contents could not be read", err)
		}
		out.Body.Items = neighbors(roots)
		if root != nil {
			at := neighbors([]graph.Neighbor{*root})[0]
			out.Body.Root = &at
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-component-neighbors", Method: http.MethodGet,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/components/{component}/around",
		Summary: "Show what is directly above and below a component",
		Description: "Returns what pulls this component in, and what it pulls in.\n\n" +
			"`above` is the direction people actually use. Somebody arrives from a finding and " +
			"asks why the component is here, which is walking up — and up is short. Walking down " +
			"is where the size lives.\n\n" +
			"A component reached several ways appears once with several parents. It is a graph " +
			"rather than a tree, so anything drawing it has to expect the same component under " +
			"many places.\n\n" +
			"A component name is not unique within a build. Where one ships at several " +
			"versions, `version` says which — without it, a name that matches more than one is " +
			"refused with 409, naming the choices, rather than guessed at.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Stream    string `path:"stream"`
		Variant   string `path:"variant"`
		Component string `path:"component" doc:"The component's name, as the findings list gives it"`
		Version   string `query:"version" doc:"The version, where the build ships that name at more than one"`
		Ecosystem string `query:"ecosystem" doc:"The ecosystem, for the few names one build holds at one version as two components"`
		Namespace string `query:"namespace" doc:"The namespace, for the few names one build holds at one version in one ecosystem as two components"`
	}) (*struct{ Body AroundBody }, error) {
		subject, target, err := browsing(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		above, below, err := graph.NewStore(in.DB.DB).Around(ctx, subject, target,
			input.Component, graph.Choice{
				Version: input.Version, Ecosystem: input.Ecosystem, Namespace: input.Namespace,
			})
		if err != nil {
			return nil, ambiguousOrMissing(err)
		}
		return &struct{ Body AroundBody }{Body: AroundBody{
			Above: neighbors(above), Below: neighbors(below),
		}}, nil
	})
}

func neighbors(rows []graph.Neighbor) []NeighborBody {
	out := make([]NeighborBody, 0, len(rows))
	for _, row := range rows {
		out = append(out, NeighborBody{
			Component: row.Name, Version: row.Version,
			Findings: row.Findings, Beneath: row.Beneath,
			BeneathBy: banded(row.BeneathBy),
			Children:  row.Children,
			Ecosystem: graph.EcosystemOf(row.Purl),
			Namespace: graph.NamespaceOf(row.Purl),
		})
	}
	return out
}

// banded folds a severity roll-up through the one place that says which words
// are real.
//
// A scanner's own "unknown", a producer's invented word and no rating at all
// are the same state everywhere that ranks or filters — only what a reader
// sees differs, and it differs by screen. Done here because the walk that
// counts a subtree cannot reach that list without an import cycle, and a copy
// of "which words are real" is exactly what one list exists to prevent.
func banded(by map[string]int) map[string]int {
	if len(by) == 0 {
		return nil
	}
	out := make(map[string]int, len(by))
	for word, n := range by {
		out[finding.BandOf(word)] += n
	}
	return out
}

// browsing resolves a build somebody may look at.
func browsing(ctx context.Context, in Ingest, product, stream, variant string) (access.Subject, int64, error) {
	subject, err := reading(ctx)
	if err != nil {
		return access.Subject{}, 0, err
	}
	named, err := locatedVisibly(ctx, in, subject, product, stream, variant)
	if err != nil {
		return access.Subject{}, 0, err
	}
	target, err := targetRow(ctx, in, named.StreamID, named.VariantID)
	if err != nil {
		return access.Subject{}, 0, err
	}
	return subject, target.ID, nil
}
