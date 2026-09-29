// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// registerCatalog registers the three groups the catalog is made of.
//
// They share the Declaring handle and nothing else. Declaring something is an
// administrator inventing a thing scans may be filed against; stating policy
// on it moves what is on a clock at all, away from the request; reading it
// answers what exists, narrowed to what the reader may see. One function
// holding all three makes the middle group — the four that silently rewrite
// what the tool reports — the hardest of the three to find.
func registerCatalog(api huma.API, d core.Declaring) {
	registerDeclaring(api, d)
	registerVariantEdits(api, d)
	registerCatalogAmends(api, d)
	registerCatalogPolicy(api, d)
	registerCatalogReading(api, d)
}
