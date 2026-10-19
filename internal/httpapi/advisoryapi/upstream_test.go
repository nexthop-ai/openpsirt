// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// An administrator inspects an upstream and trusts it with the key it names
// now; a fingerprint other than that one is refused naming what is served,
// and stopping trusting it leaves the product trusting none.
func TestAnUpstreamIsTrustedWithTheKeyItNames(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		address, roots := httpapitest.UpstreamAt(t)
		r = r.Rebuilt(func(d *core.Deps) { d.UpstreamRoots = roots })
		const path = "/v1/products/mine/upstream"

		got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, path+"/inspection", `{"url":"`+address+`"}`)
		if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Example Upstream") {
			t.Fatalf("inspecting the upstream answered %d: %s", got.Code, got.Body.String())
		}
		got = httpapitest.AsPerson(t, r, "admin", http.MethodPut, path,
			`{"url":"`+address+`","fingerprint":"ABCD"}`)
		if got.Code != http.StatusConflict {
			t.Errorf("trusting a key the upstream does not name answered %d: %s", got.Code, got.Body.String())
		}
		got = httpapitest.AsPerson(t, r, "triager", http.MethodPut, path, `{"url":"`+address+`"}`)
		if got.Code != http.StatusForbidden {
			t.Errorf("somebody who only triages trusted an upstream: %d", got.Code)
		}
		got = httpapitest.AsPerson(t, r, "admin", http.MethodPut, path, `{"url":"`+address+`"}`)
		if got.Code != http.StatusOK {
			t.Fatalf("trusting the upstream answered %d: %s", got.Code, got.Body.String())
		}
		var held struct {
			URL       string `json:"url"`
			Publisher string `json:"publisher"`
		}
		got = httpapitest.AsPerson(t, r, "admin", http.MethodGet, path, "")
		if err := json.Unmarshal(got.Body.Bytes(), &held); err != nil || held.URL != address ||
			held.Publisher != "Example Upstream" {
			t.Errorf("the product trusts %+v (%d), want the upstream named", held, got.Code)
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete, path, ""); got.Code != http.StatusNoContent {
			t.Fatalf("stopping trusting the upstream answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodGet, path, ""); got.Code != http.StatusNotFound {
			t.Errorf("a product that stopped trusting its upstream answered %d", got.Code)
		}
	})
}

// Somebody who triages the product declines one of its upstream's
// statements; to somebody who only reads it, the statement does not exist.
func TestAnUpstreamsStatementIsDeclinedBySomebodyWhoTriages(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		path := "/v1/statements/" + httpapitest.Itoa(r.UpstreamStatement(t)) + "/declined"
		if got := httpapitest.AsPerson(t, r, "reader", http.MethodPut, path, ""); got.Code != http.StatusForbidden &&
			got.Code != http.StatusNotFound {
			t.Errorf("somebody who only reads the product declined a statement: %d", got.Code)
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPut, path, ""); got.Code != http.StatusNoContent {
			t.Fatalf("declining a statement answered %d: %s", got.Code, got.Body.String())
		}
		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/components/zlib/upstream-statements", "")
		if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"declined":true`) {
			t.Errorf("the component's upstream statements answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodDelete, path, ""); got.Code != http.StatusNoContent {
			t.Errorf("restoring a statement answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// Declining, restoring and stopping trusting each change what closes the
// product's findings, so each queues the product's scanned builds to be
// scanned again in the act itself.
func TestEachUpstreamReversalQueuesTheProductsBuilds(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		address, roots := httpapitest.UpstreamAt(t)
		r = r.Rebuilt(func(d *core.Deps) { d.UpstreamRoots = roots })
		r.Scanned(t)
		statement := "/v1/statements/" + httpapitest.Itoa(r.UpstreamStatement(t)) + "/declined"
		queued := func(what string) {
			t.Helper()
			var waiting []string
			if err := r.DB.DB.NewSelect().Model((*queue.Job)(nil)).Column("reference").
				Where(`"kind" = ?`, queue.Scan).Where(`"state" = ?`, queue.Pending).
				Scan(t.Context(), &waiting); err != nil {
				t.Fatal(err)
			}
			if len(waiting) == 0 {
				t.Errorf("%s queued no scan of the product's build", what)
			}
			if _, err := r.DB.DB.NewDelete().Model((*queue.Job)(nil)).Where("1 = 1").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := r.DB.DB.NewDelete().Model((*queue.Job)(nil)).Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPut, statement, ""); got.Code != http.StatusNoContent {
			t.Fatalf("declining answered %d", got.Code)
		}
		queued("declining a statement")
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodDelete, statement, ""); got.Code != http.StatusNoContent {
			t.Fatalf("restoring answered %d", got.Code)
		}
		queued("restoring a statement")
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/products/mine/upstream",
			`{"url":"`+address+`"}`); got.Code != http.StatusOK {
			t.Fatalf("trusting answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete, "/v1/products/mine/upstream", ""); got.Code != http.StatusNoContent {
			t.Fatalf("stopping trusting answered %d", got.Code)
		}
		queued("stopping trusting the upstream")
	})
}
