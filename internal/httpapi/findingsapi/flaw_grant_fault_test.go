// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// failsNamingAFlaw makes the next read of what an issue is called fail, once
// armed.
type failsNamingAFlaw struct {
	armed *atomic.Bool
	fault *dbtest.Fault
}

func (h failsNamingAFlaw) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	if strings.Contains(e.Query, `"identifier" AS "named"`) && h.armed.CompareAndSwap(true, false) {
		h.fault.Arm("SELECT", "vulnerability")
	}
	return h.fault.BeforeQuery(ctx, e)
}

func (h failsNamingAFlaw) AfterQuery(context.Context, *bun.QueryEvent) {}

// A grant whose flaw could not be named is not made, so no notice goes out
// naming nothing.
func TestAGrantWhoseFlawCannotBeNamedIsNotMade(t *testing.T) {
	armed := &atomic.Bool{}
	fault := &dbtest.Fault{}
	httpapitest.ReachAdjusted(t, httpapitest.CastSeed.Two, func(deps *core.Deps) {
		deps.DB = dbtest.Hooked(deps.DB, failsNamingAFlaw{armed: armed, fault: fault})
	}, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFinding(t, r, true)
		at := codeFindingAt(occurrence) + "/collaborators"
		armed.Store(true)
		got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut, at+"/outsider", "")
		if !fault.Disarm() {
			t.Fatal("the grant never named its flaw, so this tested nothing")
		}
		if got.Code != http.StatusInternalServerError {
			t.Errorf("a grant whose flaw could not be named answered %d: %s", got.Code, got.Body)
		}
		listed := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodGet, at, "")
		if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "outsider") {
			t.Errorf("after the failed grant the collaborators read %d: %s", listed.Code, listed.Body)
		}
	})
}
