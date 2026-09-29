// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestADuplicateRulingSaysTheDateItStartsAndRecordsIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		minted := r.Embargoed(t)
		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/reports",
			`{"summary":"The management socket lets anybody in.","received":"2026-01-10"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording a claim answered %d: %s", got.Code, got.Body.String())
		}
		var claimed struct {
			Reference string `json:"reference"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &claimed); err != nil {
			t.Fatal(err)
		}
		want := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC).Add(90 * 24 * time.Hour).
			Format(time.RFC3339)

		preview := "/v1/products/mine/issues/" + minted + "/duplicate-disclosure?report=" +
			claimed.Reference
		var starts struct {
			DiscloseAt    string `json:"disclose_at"`
			NeedsApproval bool   `json:"needs_approval"`
		}
		httpapitest.Read(t, r, "private-triage", preview, &starts)
		// The flaw already ends ninety days from now, so bringing it in to
		// April is a shortening past the threshold.
		if starts.DiscloseAt != want || !starts.NeedsApproval {
			t.Errorf("the preview says %+v, want %s waiting for a second person", starts, want)
		}
		// Asked under the rule proposing the ruling is.
		if code := r.As(t, "private", http.MethodGet, preview); code != http.StatusForbidden {
			t.Errorf("a private reader previewing answered %d", code)
		}

		got = httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/report-rulings",
			fmt.Sprintf(`{"reports":[%q],"disposition":"duplicate","duplicate_of":%q}`,
				claimed.Reference, minted))
		if got.Code != http.StatusCreated {
			t.Fatalf("a duplicate answered %d: %s", got.Code, got.Body.String())
		}
		var ruling rulingRead
		if err := json.Unmarshal(got.Body.Bytes(), &ruling); err != nil {
			t.Fatal(err)
		}
		var moved struct {
			Items []struct {
				Act    string `json:"act"`
				Was    string `json:"was"`
				Until  string `json:"until"`
				Ruling int64  `json:"ruling"`
				Report string `json:"report"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "private-triage",
			"/v1/products/mine/issues/"+minted+"/disclosure", &moved)
		if len(moved.Items) != 1 {
			t.Fatalf("the embargo's record reads %+v, want the ruling's movement", moved.Items)
		}
		row := moved.Items[0]
		if row.Act != "duplicate" || row.Until != want || row.Was == "" ||
			row.Ruling != ruling.ID || row.Report != claimed.Reference {
			t.Errorf("the movement reads %+v, want a duplicate to %s by ruling %d from %s",
				row, want, ruling.ID, claimed.Reference)
		}
	})
}
