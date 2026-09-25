// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// registerTags is the words people put on findings.
//
// People tag work regardless. With nowhere to put it they do it inside the
// reasoning text, where nothing can filter on it and an approver reads it as
// part of the argument.
func registerTags(api huma.API, in Ingest) {
	const at = "/v1/products/{product}/streams/{stream}/variants/{variant}" +
		"/findings/{vulnerability}/components/{component}/tags/{tag}"

	tagging := func(add bool) func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability"`
		Component     string `path:"component"`
		ComponentQuery
		Tag string `path:"tag" maxLength:"191" doc:"The word, matched without regard to capitals"`
	}) (*struct{}, error) {
		return func(ctx context.Context, input *struct {
			Product       string `path:"product"`
			Stream        string `path:"stream"`
			Variant       string `path:"variant"`
			Vulnerability string `path:"vulnerability"`
			Component     string `path:"component"`
			ComponentQuery
			Tag string `path:"tag" maxLength:"191" doc:"The word, matched without regard to capitals"`
		}) (*struct{}, error) {
			subject, err := reading(ctx)
			if err != nil {
				return nil, err
			}
			product, _, issue, component, err := locateFinding(ctx, in, subject,
				input.Product, input.Stream, input.Variant, input.Vulnerability, input.Component,
				input.choice())
			if err != nil {
				return nil, err
			}
			store := finding.NewStore(in.DB.DB)
			if add {
				err = store.TagIt(ctx, subject, product, issue, component, input.Tag)
			} else {
				err = store.Untag(ctx, subject, product, issue, component, input.Tag)
			}
			if err != nil {
				return nil, refusedFinding(in, err)
			}
			return &struct{}{}, nil
		}
	}

	huma.Register(api, requiring(huma.Operation{
		OperationID: "tag-finding", Method: http.MethodPut, Path: at,
		Summary: "Tag a finding with a word",
		Description: "Puts a free-text tag on one issue in one component of this product.\n\n" +
			"No fixed vocabulary, because none has been earned yet. A tag that becomes " +
			"universal is a signal that it should be promoted to a real concept — \"waiting on " +
			"vendor\" is a state the tool would want to reason about rather than a string " +
			"somebody typed.\n\n" +
			"One issue in one component of one product, not one place and not one build: " +
			"a kernel flaw at sixty places is one thing somebody is tagging, and a tag is " +
			"about the work rather than about a release.\n\n" +
			"Matched without regard to capitals and shown back as it was typed. Tagging what " +
			"already carries the tag succeeds and keeps the first spelling.\n\n" +
			"Tagging is triage, so it asks for the triage right: a tag changes what a " +
			"filtered list answers, and somebody who may only read should not move work into " +
			"or out of a saved filter.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "", triageRights()...), tagging(true))

	huma.Register(api, requiring(huma.Operation{
		OperationID: "untag-finding", Method: http.MethodDelete, Path: at,
		Summary: "Take a tag off a finding",
		Description: "Removes a tag. Taking off one that is not there succeeds and changes " +
			"nothing.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "", triageRights()...), tagging(false))

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-tags", Method: http.MethodGet, Path: "/v1/products/{product}/tags",
		Summary: "List a product's tags",
		Description: "Every tag anybody has used here, most-used first.\n\n" +
			"What a filter offers rather than a vocabulary: the list is what people have " +
			"actually written, which is also the evidence for promoting one of them to a " +
			"real concept.\n\n" +
			"Only the words on findings you may read. A tag row carries no visibility of " +
			"its own, so the list is narrowed by the findings it was written on — reading it " +
			"is a read act, and writing one is the act that asks for triage.",
		Tags: []string{"Findings"},
	}, perProduct, "Answers only the words on findings you may see.",
		readRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*listOutput[string], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		named, err := productNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.logger())
		}
		rows, err := finding.NewStore(in.DB.DB).TagsInUse(ctx, subject, named.ID)
		if err != nil {
			return nil, wentWrong(in.logger(), "the tags could not be read", err)
		}
		out := &listOutput[string]{}
		out.Body.Items = rows
		if out.Body.Items == nil {
			out.Body.Items = []string{}
		}
		return out, nil
	})
}
