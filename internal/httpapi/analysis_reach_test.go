// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// An analysis result reaches none of the consumers of vulnerability findings,
// at any visibility: the lists and their counts, the exports and the VEX
// document. Each read below would carry it on its visibility alone, since a
// lead moved into a private case is private and only its kind keeps it out.
func TestAnAnalysisResultReachesNoConsumerOfVulnerabilityFindings(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		hidden := r.Embargoed(t)
		r.ScannedTwoIssues(t)
		const internal, shown = "CVE-2026-1000", "CVE-2026-9999"
		lead := func(identifier, visibility string) {
			t.Helper()
			r.PatchedRows(t, `UPDATE "finding" SET "kind" = 'analysis', "visibility" = '`+visibility+`'
				WHERE "vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = '`+identifier+`')`)
		}
		lead(internal, "internal")
		lead(hidden, "private")

		type listed struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
			} `json:"items"`
			Total int `json:"total"`
		}
		for _, path := range []string{"/v1/products/mine/findings", "/v1/findings", "/v1/unassigned"} {
			for _, who := range []string{"private", "internal-triager"} {
				var out listed
				httpapitest.Read(t, r, who, path, &out)
				seen := map[string]bool{}
				for _, item := range out.Items {
					seen[item.Vulnerability] = true
				}
				if seen[internal] || seen[hidden] {
					t.Errorf("%s: %s reads an analysis result: %v", path, who, seen)
				}
				if out.Total != len(out.Items) {
					t.Errorf("%s: %s is counted %d findings and listed %d", path, who, out.Total, len(out.Items))
				}
			}
		}
		// The private reader reads the vulnerability beside them, so the
		// absence above is the kind rather than an empty list.
		var mine listed
		httpapitest.Read(t, r, "private", "/v1/products/mine/findings", &mine)
		if len(mine.Items) == 0 || mine.Items[0].Vulnerability != shown {
			t.Errorf("a reader of both halves reads %+v, want the scanned vulnerability", mine.Items)
		}

		const build = "/v1/products/mine/streams/master/variants/broadcom"
		for _, path := range []string{"/v1/products/mine/findings.csv", build + "/register.csv"} {
			for _, who := range []string{"private", "internal-triager"} {
				got := httpapitest.AsPerson(t, r, who, http.MethodGet, path, "")
				if got.Code != http.StatusOK {
					t.Fatalf("%s: %s exporting answered %d: %s", path, who, got.Code, got.Body.String())
				}
				if body := got.Body.String(); strings.Contains(body, internal) || strings.Contains(body, hidden) {
					t.Errorf("%s: %s exports an analysis result:\n%s", path, who, body)
				}
			}
			got := httpapitest.AsPerson(t, r, "private", http.MethodGet, path, "")
			if !strings.Contains(got.Body.String(), shown) {
				t.Errorf("%s: a reader of both halves exports nothing of the vulnerability:\n%s", path, got.Body.String())
			}
		}

		// An agreed decision is stated in the build's VEX document, and the
		// same row as an analysis result is not, though it is public, which
		// no lead is.
		claim, _ := r.Claimed(t, "triager", shown, "linux-image", httpapitest.Dismissal)
		r.Agreed(t, claim)
		stated := func() bool {
			for _, statement := range r.VexStatements(t) {
				if statement[0] == shown {
					return true
				}
			}
			return false
		}
		if !stated() {
			t.Fatal("the decided vulnerability is not stated, so the document checks nothing")
		}
		lead(shown, "public")
		if stated() {
			t.Error("the build's VEX document states an analysis result")
		}
	})
}
