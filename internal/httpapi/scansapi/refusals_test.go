// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/refusaltest"
)

// The one mapper here is reached only with an error something has already
// classified, so a lost connection never arrives at it. A mapper added beside
// it fails this until it is checked or exempt.
func TestEveryRefusalMapperIsCheckedOrExempt(t *testing.T) {
	refusaltest.CoversEveryMapper(t, nil, map[string]string{
		"rejection": "an upload refused by a rule the ingest names",
	})
}
