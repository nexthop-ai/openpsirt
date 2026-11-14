// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"sort"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// namedByProxy marks a request the trusted proxy named somebody on.
type namedByProxy struct{}

// ProvidersBody is the ways in, and whether the proxy named the browser asking.
type ProvidersBody struct {
	Items []ProviderBody `json:"items"`
	// NamedByProxy lets a browser the proxy named, and that is refused here,
	// show the screen a refused sign-in lands on. It is the same for every
	// reason a person is refused.
	NamedByProxy bool `json:"named_by_proxy,omitempty" doc:"Whether the trusted proxy in front of this deployment named the person asking. Where it did and the read of the current user is refused, they were refused, for a reason this does not say"`
}

type providersAnswer struct {
	CacheControl string `header:"Cache-Control" doc:"Always no-store"`
	Body         ProvidersBody
}

// ProviderBody is one way in.
type ProviderBody struct {
	Name string `json:"name" doc:"The segment in the sign-in path"`
	Path string `json:"path" doc:"The address to send the browser to"`
}

func registerProviders(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-sign-in-providers", Method: http.MethodGet, Path: "/v1/sign-in",
		Summary: "List sign-in providers",
		Description: "Returns the sign-in providers this deployment has configured, so a " +
			"sign-in page can offer them.\n\n" +
			"Answered without a credential, because it is what somebody sees before they " +
			"have one. It is the only reading endpoint that is. It reports names an " +
			"operator configured, and whether the trusted proxy in front of this deployment " +
			"named the person asking.",
		Tags: []string{"Access"},
	}, core.NoCredential, ""), func(ctx context.Context, _ *struct{}) (*providersAnswer, error) {
		in := core.Of(ctx, in)
		// The answer turns on who is asking, through the proxy's header, and
		// is read without a credential, so no cache may hand it to another
		// browser.
		out := &providersAnswer{CacheControl: "no-store"}
		out.Body.NamedByProxy, _ = ctx.Value(namedByProxy{}).(bool)
		out.Body.Items = make([]ProviderBody, 0, len(in.Providers))
		for name := range in.Providers {
			out.Body.Items = append(out.Body.Items, ProviderBody{
				Name: name, Path: "/v1/sign-in/" + name,
			})
		}
		sort.Slice(out.Body.Items, func(i, j int) bool {
			return out.Body.Items[i].Name < out.Body.Items[j].Name
		})
		return out, nil
	})
}
