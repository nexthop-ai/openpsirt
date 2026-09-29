// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// done drives one request as the administrator and fails on a refusal.
func done(t *testing.T, r *httpapitest.Reach, method, path, body string) {
	t.Helper()
	if got := httpapitest.AsPerson(t, r, "admin", method, path, body); got.Code >= 300 {
		t.Fatalf("%s %s answered %d: %s", method, path, got.Code, got.Body.String())
	}
}

// trailSince is the rows written since a count was taken, newest first.
func trailSince(t *testing.T, r *httpapitest.Reach, before int) httpapitest.Changed {
	t.Helper()
	var trail httpapitest.Changed
	httpapitest.Read(t, r, "admin", "/v1/administration/changes?limit=10", &trail)
	if n := trail.Total - before; n < len(trail.Items) {
		trail.Items = trail.Items[:n]
	}
	return trail
}

func trailCount(t *testing.T, r *httpapitest.Reach) int {
	t.Helper()
	var trail httpapitest.Changed
	httpapitest.Read(t, r, "admin", "/v1/administration/changes?limit=1", &trail)
	return trail.Total
}

func TestBringingBackWhatWasRetiredIsRecordedLikeRetiringIt(t *testing.T) {
	// Declaring a retired product, release or variant again brings it back
	// into use, which undoes a retirement the trail records. Who brought it
	// back is the same question as who retired it.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		done(t, r, http.MethodPost, "/v1/products/mine/streams", `{"name":"v9","kind":"tag"}`)
		done(t, r, http.MethodPost, "/v1/products/mine/variants", `{"name":"lab"}`)
		for _, each := range []struct {
			retire, declare, body, about string
		}{
			{"/v1/products/mine/streams/v9", "/v1/products/mine/streams",
				`{"name":"v9","kind":"tag"}`, "mine v9"},
			{"/v1/products/mine/variants/lab", "/v1/products/mine/variants",
				`{"name":"lab"}`, "mine lab"},
			{"/v1/products/theirs", "/v1/products", `{"name":"theirs"}`, "theirs"},
		} {
			done(t, r, http.MethodDelete, each.retire, "")
			before := trailCount(t, r)
			done(t, r, http.MethodPost, each.declare, each.body)
			trail := trailSince(t, r, before)
			if len(trail.Items) != 1 || trail.Items[0].Kind != "catalog" ||
				trail.Items[0].About != each.about || trail.Items[0].Became != "in use" ||
				!trail.Items[0].Unset {
				t.Errorf("bringing back %s recorded %+v", each.about, trail.Items)
			}

			// Declaring what is already in use changes nothing and records
			// nothing, which is what lets a pipeline run it on every build.
			before = trailCount(t, r)
			done(t, r, http.MethodPost, each.declare, each.body)
			if trail := trailSince(t, r, before); len(trail.Items) != 0 {
				t.Errorf("declaring %s again recorded %+v", each.about, trail.Items)
			}
		}
	})
}

func TestFillingInWhatATagWasCutFromIsRecorded(t *testing.T) {
	// What a tag was cut from is a release detail the trail records, however
	// it arrives: declared again with a parent, or set beside its date.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		cutFrom := func(t *testing.T, trail httpapitest.Changed, about string) {
			t.Helper()
			for _, row := range trail.Items {
				if row.Kind == "release" && row.About == about && row.Became == "master" {
					return
				}
			}
			t.Errorf("filling in what %s was cut from recorded %+v", about, trail.Items)
		}

		done(t, r, http.MethodPost, "/v1/products/mine/streams", `{"name":"v8","kind":"tag"}`)
		before := trailCount(t, r)
		done(t, r, http.MethodPost, "/v1/products/mine/streams",
			`{"name":"v8","kind":"tag","parent":"master"}`)
		cutFrom(t, trailSince(t, r, before), "mine v8 cut from")

		done(t, r, http.MethodPost, "/v1/products/mine/streams", `{"name":"v7","kind":"tag"}`)
		before = trailCount(t, r)
		done(t, r, http.MethodPut, "/v1/products/mine/streams/v7/release",
			`{"released_on":"2026-03-31","cut_from":"master"}`)
		cutFrom(t, trailSince(t, r, before), "mine v7 cut from")
	})
}
