// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestAReleaseIsMarkedAffectedBySomebodyWhoTriagesIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		flaw := r.Embargoed(t)
		named := httpapitest.AdvisoryOver(t, r, "private-triage", "mine", flaw)
		releases := "/v1/advisories/" + named + "/releases"
		marked := "/v1/advisories/" + named + "/marked"
		mark := func(branchOrTag string) string {
			return `{"product":"mine","vulnerability":"` + flaw + `","branch_or_tag":"` + branchOrTag +
				`","variant":"broadcom","affected":true}`
		}
		type listing struct {
			Items []struct {
				BranchOrTag string `json:"branch_or_tag"`
				Marked      bool   `json:"marked"`
			} `json:"items"`
		}

		var before listing
		httpapitest.Read(t, r, "private-triage", releases, &before)
		if len(before.Items) == 0 || before.Items[0].Marked {
			t.Fatalf("the releases read %+v before anything was marked", before.Items)
		}

		// Somebody who reads the product and triages none of it.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private", http.MethodPut,
			marked, mark("master")), http.StatusForbidden)
		// A release the issue is not in.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private-triage", http.MethodPut,
			marked, mark("no-such-stream")), http.StatusNotFound)

		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPut,
			marked, mark("master")); got.Code != http.StatusNoContent {
			t.Fatalf("marking a release answered %d: %s", got.Code, got.Body.String())
		}
		var after listing
		httpapitest.Read(t, r, "private-triage", releases, &after)
		if len(after.Items) == 0 || !after.Items[0].Marked {
			t.Errorf("the marked release reads %+v", after.Items)
		}

		// The releases and the document each name the edition they were read
		// at, the one the advisory names, so a screen agrees to what it shows.
		var it struct {
			Edition int `json:"edition"`
		}
		httpapitest.Read(t, r, "private-triage", "/v1/advisories/"+named, &it)
		for _, path := range []string{releases, "/v1/advisories/" + named + "/document"} {
			got := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet, path, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s answered %d: %s", path, got.Code, got.Body.String())
			}
			if edition := got.Header().Get("Advisory-Edition"); edition != strconv.Itoa(it.Edition) || it.Edition < 2 {
				t.Errorf("%s names edition %q after the mark, want %d", path, edition, it.Edition)
			}
		}
	})
}

func TestAnAdvisoryIsListedByWhatItCoversAndAgreedToBySomebodyElse(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		flaw := r.Embargoed(t)
		other := r.Embargoed(t)
		named := httpapitest.AdvisoryOver(t, r, "private-triage", "mine", flaw)

		type listing struct {
			Total int `json:"total"`
		}
		var covering, notCovering listing
		httpapitest.Read(t, r, "private-triage", "/v1/advisories?product=mine&issue="+flaw, &covering)
		httpapitest.Read(t, r, "private-triage", "/v1/advisories?product=mine&issue="+other, &notCovering)
		if covering.Total != 1 || notCovering.Total != 0 {
			t.Errorf("narrowed to what it covers the list holds %d, and to another flaw %d",
				covering.Total, notCovering.Total)
		}

		approval := "/v1/advisories/" + named + "/approval"
		read := httpapitest.AgreeingTo(t, r, "private-dispatcher", "/v1/advisories/"+named)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			approval, read), http.StatusConflict)
		// An edition other than the one it says now was not what was read.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost,
			approval, `{"edition":99}`), http.StatusConflict)
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost,
			approval, read); got.Code != http.StatusCreated {
			t.Fatalf("somebody else agreeing answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodDelete,
			approval, ""); got.Code != http.StatusNoContent {
			t.Fatalf("taking the agreement back answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private-triage", http.MethodDelete,
			approval, ""), http.StatusUnprocessableEntity)
	})
}
