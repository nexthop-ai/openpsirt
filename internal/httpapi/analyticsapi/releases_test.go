// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// The releases list counts what is open in each build, and a product
// somebody may not read answers exactly as a product nobody declared: one
// that is hidden, and one that is seen and holds nothing they may read.
func TestTheReleasesListAnswersAnUnreadableProductAsUndeclared(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		var releases struct {
			Items []struct {
				BranchOrTag string `json:"branch_or_tag"`
				Variant     string `json:"variant"`
				Open        int    `json:"open"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/releases", &releases)
		found := false
		for _, one := range releases.Items {
			if one.BranchOrTag == "master" && one.Variant == "broadcom" {
				found = true
				if one.Open == 0 {
					t.Errorf("the scanned build counts nothing open: %+v", one)
				}
			}
		}
		if !found {
			t.Fatalf("the releases list holds no row for the scanned build: %+v", releases.Items)
		}

		undeclared := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet,
			"/v1/products/nobody-declared-this/releases", "")
		if undeclared.Code != http.StatusNotFound {
			t.Fatalf("a product nobody declared answered %d: %s", undeclared.Code, undeclared.Body.String())
		}
		// The outsider sees no product. The administrator sees every product
		// and is granted no reading in any.
		for _, who := range []string{"outsider", "admin"} {
			got := httpapitest.AsPerson(t, r, who, http.MethodGet, "/v1/products/mine/releases", "")
			if got.Code != undeclared.Code || got.Body.String() != undeclared.Body.String() {
				t.Errorf("%s reading the releases answered %d %s, want what an undeclared product answers: %s",
					who, got.Code, got.Body.String(), undeclared.Body.String())
			}
		}
	})
}

// TestTheReleaseTrendRefusesARequestNamingNoProduct pins the refusal of a
// release trend asked across products, since one product's tags interleave
// with another's by date and an empty answer reads as no releases cut.
func TestTheReleaseTrendRefusesARequestNamingNoProduct(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTag(t, "v1.0", "3.7.0")
		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/trend/releases", "")
		if got.Code != http.StatusUnprocessableEntity || !strings.Contains(got.Body.String(), "a product must be named") {
			t.Errorf("a release trend naming no product answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// TestReleaseNotesLeadWithWhatTheLaterBuildWasMeasuredWith pins the lead
// line's provenance: the scanner, its version, the vulnerability data and the
// day of the last finished run against the later build.
func TestReleaseNotesLeadWithWhatTheLaterBuildWasMeasuredWith(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		// The run left unfinished, as one still going.
		if _, err := r.DB.DB.NewUpdate().Table("scan_run").Set(`"finished_at" = NULL`).
			Where(`"build_id" = ?`, r.BuildOf(t, httpapitest.SeededBuild)).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		const notes = "/v1/products/mine/comparison/notes" +
			"?from=master&from_variant=broadcom&to=master&to_variant=broadcom"
		unfinished := httpapitest.AsPerson(t, r, "triager", http.MethodGet, notes, "")
		if unfinished.Code != http.StatusOK {
			t.Fatalf("release notes answered %d: %s", unfinished.Code, unfinished.Body.String())
		}
		if strings.Contains(unfinished.Body.String(), "measured") {
			t.Errorf("notes over a build no run finished name what measured it:\n%s", unfinished.Body.String())
		}

		finished := time.Date(2026, 9, 14, 8, 30, 0, 0, time.UTC)
		if _, err := r.DB.DB.NewUpdate().Table("scan_run").Set(`"finished_at" = ?`, finished).
			Where(`"build_id" = ?`, r.BuildOf(t, httpapitest.SeededBuild)).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, notes, "")
		if got.Code != http.StatusOK {
			t.Fatalf("release notes answered %d: %s", got.Code, got.Body.String())
		}
		const want = "Last measured 2026-09-14, measured with grype 0.112.0 against vulnerability data of 2026-08-28"
		if !strings.Contains(got.Body.String(), want) {
			t.Errorf("the notes do not say %q:\n%s", want, got.Body.String())
		}
	})
}
