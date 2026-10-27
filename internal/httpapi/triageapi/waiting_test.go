// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/triageapi"
)

// The demo's seeders read a waiting decision's identifier off the review queue by
// name (Makefile.demo, which nothing else runs). A name changed here leaves the
// demo approving nothing.
func TestAWaitingDecisionOpensWithItsIdentifier(t *testing.T) {
	waiting, err := json.Marshal(triageapi.WaitingBody{Decision: triageapi.DecisionBody{ID: 7}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(waiting), `{"decision":{"id":7`) {
		t.Errorf("a waiting decision reads as %s, not opening with its identifier", waiting)
	}
}
