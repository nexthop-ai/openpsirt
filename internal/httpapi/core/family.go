// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// Family is the query parameter keeping a list of held work to one family of
// finding, offering the families the kind package declares rather than
// naming them again.
type Family string

// Schema offers every family, in the order a screen draws them.
func (Family) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(kind.Families()))
	for _, each := range kind.Families() {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}
