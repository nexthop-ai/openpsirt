// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/triageapi"
)

// The demo's seeders read a waiting claim's identifier off the review queue by
// name (Makefile.demo, which nothing else runs). A name changed here leaves the
// demo approving nothing.
func TestAWaitingClaimOpensWithItsIdentifier(t *testing.T) {
	waiting, err := json.Marshal(triageapi.WaitingBody{Claim: triageapi.ClaimBody{ID: 7}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(waiting), `{"claim":{"id":7`) {
		t.Errorf("a waiting claim reads as %s, not opening with its identifier", waiting)
	}
}
