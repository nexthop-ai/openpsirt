// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
)

// The addresses build pipelines called before the API paths were renamed,
// which keep answering with no removal planned. Each takes the parameter
// names of the operation it stands for, because the handler reads them by
// name; a caller never sees a parameter's name.
const (
	FormerUpload        = "/v1/products/{product}/streams/{stream}/variants/{variant}/scans"
	FormerUploadChanges = FormerUpload + "/{sbom}/changes"
)

// RegisterWithFormer registers an operation at its path and again at each
// former address, which answers through the same declaration, middleware and
// handler. A former address is left out of the published document, so a new
// integration finds the one path, and is marked nothing, because it stays.
func RegisterWithFormer[I, O any](to huma.API, op huma.Operation,
	handler func(context.Context, *I) (*O, error), former ...string) {
	huma.Register(to, op, handler)
	for _, path := range former {
		alias := op
		alias.Path = path
		alias.Hidden = true
		huma.Register(to, alias, handler)
	}
}
