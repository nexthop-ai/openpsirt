// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// registerLabels is the words people put on findings.
//
// People label work regardless. With nowhere to put it they do it inside the
// reasoning text, where nothing can filter on it and an approver reads it as
// part of the argument.
func registerLabels(api huma.API, in core.Deps) {
	const at = "/v1/products/{product}/branches-and-tags/{stream}/variants/{variant}" +
		"/findings/{issue}/components/{component}/labels/{label}"

	labeling := func(add bool) func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"issue"`
		Component     string `path:"component"`
		core.ComponentQuery
		Label string `path:"label" maxLength:"191" doc:"The word, matched without regard to capitals"`
	}) (*struct{}, error) {
		return func(ctx context.Context, input *struct {
			Product       string `path:"product"`
			Stream        string `path:"stream"`
			Variant       string `path:"variant"`
			Vulnerability string `path:"issue"`
			Component     string `path:"component"`
			core.ComponentQuery
			Label string `path:"label" maxLength:"191" doc:"The word, matched without regard to capitals"`
		}) (*struct{}, error) {
			subject, err := core.Reading(ctx)
			if err != nil {
				return nil, err
			}
			product, _, issue, component, err := locateFinding(ctx, in, subject,
				input.Product, input.Stream, input.Variant, input.Vulnerability, input.Component,
				input.Choice())
			if err != nil {
				return nil, err
			}
			store := finding.NewStore(in.DB.DB)
			if add {
				err = store.LabelIt(ctx, subject, product, issue, component, input.Label)
			} else {
				err = store.Unlabel(ctx, subject, product, issue, component, input.Label)
			}
			if err != nil {
				return nil, core.RefusedFinding(in, err)
			}
			return &struct{}{}, nil
		}
	}

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "label-finding", Method: http.MethodPut, Path: at,
		Summary: "Label a finding",
		Description: "Puts a free-text label on one issue in one component of this product.\n\n" +
			"No fixed vocabulary, because none has been earned yet. A label that becomes " +
			"universal is a signal that it should be promoted to a real concept — \"waiting on " +
			"vendor\" is a state the tool would want to reason about rather than a string " +
			"somebody typed.\n\n" +
			"One issue in one component of one product, not one occurrence and not one build: " +
			"a kernel flaw at sixty occurrences is one thing somebody is labeling, and a label is " +
			"about the work rather than about a release.\n\n" +
			"Matched without regard to capitals and shown back as it was typed. Labeling what " +
			"already carries the label succeeds and keeps the first spelling.\n\n" +
			"Labeling is triage, so it asks for the triage right: a label changes what a " +
			"filtered list answers, and somebody who may only read should not move work into " +
			"or out of a saved filter.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "", core.TriageRights()...), labeling(true))

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "unlabel-finding", Method: http.MethodDelete, Path: at,
		Summary: "Take a label off a finding",
		Description: "Removes a label. Taking off one that is not there succeeds and changes " +
			"nothing.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "", core.TriageRights()...), labeling(false))

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-labels", Method: http.MethodGet, Path: "/v1/products/{product}/labels",
		Summary: "List a product's labels",
		Description: "Every label anybody has used here, most-used first.\n\n" +
			"What a filter offers rather than a vocabulary: the list is what people have " +
			"actually written, which is also the evidence for promoting one of them to a " +
			"real concept.\n\n" +
			"Only the words on findings you may read. A label row carries no visibility of " +
			"its own, so the list is narrowed by the findings it was written on — reading it " +
			"is a read act, and writing one is the act that asks for triage.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "Answers only the words on findings you may see.",
		core.ReadRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*core.ListOutput[string], error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		named, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		rows, err := finding.NewStore(in.DB.DB).LabelsInUse(ctx, subject, named.ID)
		switch {
		case errors.Is(err, access.ErrDenied):
			return nil, core.NoSuchProduct()
		case err != nil:
			return nil, core.WentWrong(in.Log(), "the labels could not be read", err)
		}
		out := &core.ListOutput[string]{}
		out.Body.Items = rows
		if out.Body.Items == nil {
			out.Body.Items = []string{}
		}
		return out, nil
	})
}
