// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/analyticsapi"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestADecisionInTheRecordCountsEveryStateAnOccurrenceCanBeIn(t *testing.T) {
	// A state the store adds joins the one-word state and can make a decision
	// read "mixed", so the counts beside it have to carry it too.
	var counted []string
	shape := reflect.TypeFor[analyticsapi.StatesBody]()
	for field := range shape.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		counted = append(counted, name)
	}
	if len(counted) == 0 {
		t.Fatal("no counts were found, so this checked nothing")
	}
	for _, state := range triage.States() {
		if !slices.Contains(counted, string(state)) {
			t.Errorf("an occurrence can be %q, and the record's counts have no field for it", state)
		}
	}
	for _, name := range counted {
		if !slices.Contains(triage.States(), triage.State(name)) {
			t.Errorf("the record counts %q, which is no state an occurrence can be in", name)
		}
	}
}
