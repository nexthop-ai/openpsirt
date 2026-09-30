// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/reportsapi"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestAClaimInTheRecordCountsEveryStateADecisionCanBeIn(t *testing.T) {
	// A state the store adds joins the one-word state and can make a claim
	// read "mixed", so the counts beside it have to carry it too.
	var counted []string
	shape := reflect.TypeFor[reportsapi.StatesBody]()
	for field := range shape.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		counted = append(counted, name)
	}
	if len(counted) == 0 {
		t.Fatal("no counts were found, so this checked nothing")
	}
	for _, state := range triage.States() {
		if !slices.Contains(counted, string(state)) {
			t.Errorf("a decision can be %q, and the record's counts have no field for it", state)
		}
	}
	for _, name := range counted {
		if !slices.Contains(triage.States(), triage.State(name)) {
			t.Errorf("the record counts %q, which is no state a decision can be in", name)
		}
	}
}
