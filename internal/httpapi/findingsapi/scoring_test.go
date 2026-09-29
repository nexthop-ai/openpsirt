// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A vector is scored with the band it falls in; a blank one and one on a
// scheme not scored here are the caller's to fix. Verified by deleting the
// blank-vector check: a vector of spaces is then answered as unscorable
// rather than as unstated.
func TestAVectorIsScoredAndAnUnscorableOneRefused(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		var scored struct {
			Vector   string  `json:"vector"`
			Version  string  `json:"version"`
			Score    float64 `json:"score"`
			Severity string  `json:"severity"`
		}
		httpapitest.Read(t, r, "reader", "/v1/score?vector="+
			url.QueryEscape("cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h"), &scored)
		if scored.Score != 9.8 || scored.Severity != "critical" ||
			scored.Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
			t.Errorf("a critical vector scored as %+v", scored)
		}

		blank := httpapitest.AsPerson(t, r, "reader", http.MethodGet, "/v1/score?vector=%20%20", "")
		httpapitest.RefusedWith(t, blank, http.StatusUnprocessableEntity)
		if !httpapitest.Contains(blank.Body.String(), "state a vector") {
			t.Errorf("a blank vector is not told to state one: %s", blank.Body.String())
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, "/v1/score?vector="+
			url.QueryEscape("AV:N/AC:L/Au:N/C:P/I:P/A:P"), ""), http.StatusUnprocessableEntity)
	})
}
