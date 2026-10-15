// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"net/url"
	"sort"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
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
		// Parsed here rather than through the address's own reader, which
		// drops a pair it cannot read — a malformed escape, a semicolon — and
		// says nothing. Dropped, the filter that pair carried is read as
		// absent and the unfiltered list answers.
		address := ctx.URL()
		query, err := url.ParseQuery(address.RawQuery)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusBadRequest,
				"the query string could not be read: "+err.Error())
			return
		}
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

// refuseNUL answers 400 to a request carrying a NUL character in a query
// parameter or a path value, naming the input. A form field is checked where
// the form is read, and a JSON body by the format that reads it.
//
// Registered after unknown parameters are refused, so a parameter the
// operation does not take is refused as that first.
func refuseNUL(api huma.API) {
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		op := ctx.Operation()
		if op == nil {
			next(ctx)
			return
		}
		// The query was readable, or the request was refused above.
		query, _ := url.ParseQuery(ctx.URL().RawQuery)
		if at, found := core.NULInValues("query parameter", query); found {
			_ = huma.WriteErr(api, ctx, http.StatusBadRequest, core.RefusalOfNUL(at))
			return
		}
		for _, param := range op.Parameters {
			if param.In == "path" && core.HoldsNUL(ctx.Param(param.Name)) {
				_ = huma.WriteErr(api, ctx, http.StatusBadRequest, core.RefusalOfNUL("path value "+param.Name))
				return
			}
		}
		next(ctx)
	})
}
