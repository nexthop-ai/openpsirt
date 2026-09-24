// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"sort"

	"github.com/danielgtaylor/huma/v2"
)

// refuseUnknownParameters answers 400 to a request carrying a query parameter
// its operation does not declare, naming the parameter.
//
// An ignored parameter is a filter that did nothing: a mistyped `stat=open`
// returns the unfiltered list, which reads as a correct answer. Read off each
// operation's own declaration, so a parameter a handler takes is one the
// document publishes and nothing is listed twice.
//
// Registered after the declarations are enforced, so a caller who may not
// reach an operation is refused as that before anything about the request is
// examined.
func refuseUnknownParameters(api huma.API) {
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		op := ctx.Operation()
		if op == nil {
			next(ctx)
			return
		}
		address := ctx.URL()
		query := address.Query()
		if len(query) == 0 {
			next(ctx)
			return
		}
		takes := map[string]bool{}
		for _, param := range op.Parameters {
			if param.In == "query" {
				takes[param.Name] = true
			}
		}
		// Sorted, so a request carrying two is refused naming the same one
		// every time.
		sent := make([]string, 0, len(query))
		for name := range query {
			sent = append(sent, name)
		}
		sort.Strings(sent)
		for _, name := range sent {
			if !takes[name] {
				_ = huma.WriteErr(api, ctx, http.StatusBadRequest,
					"unknown query parameter "+name+": this operation does not take it")
				return
			}
		}
		next(ctx)
	})
}
