package httpapi

import (
	"context"
	"net/http"
	"sort"

	"github.com/danielgtaylor/huma/v2"
)

// ProviderBody is one way in.
type ProviderBody struct {
	Name string `json:"name" doc:"What to put in the sign-in path"`
	Path string `json:"path" doc:"Where to send the browser to start"`
}

func registerProviders(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-sign-in-providers", Method: http.MethodGet, Path: "/v1/sign-in",
		Summary: "List the ways in",
		Description: "Returns the sign-in providers this deployment has configured, so a " +
			"sign-in page can offer them.\n\n" +
			"**Answered without a credential**, because it is what somebody sees before they " +
			"have one. It is the only reading endpoint that is, and it reports names an " +
			"operator configured and nothing else — no account exists or does not exist as far " +
			"as this is concerned, which is the disclosure that would matter.",
		Tags: []string{"Access"},
	}, noCredential, ""), func(_ context.Context, _ *struct{}) (*listOutput[ProviderBody], error) {
		out := &listOutput[ProviderBody]{}
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
