// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestAFindingSaysWhetherItIsDisclosed(t *testing.T) {
	// Everything about disclosure existed in the API and appeared nowhere
	// a person could see it: an undisclosed recorded flaw rendered as
	// "Unrated · Undecided · 1 location", identical to any other row — so
	// somebody could say something about it without ever being told not
	// to.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)

		var row struct {
			Items []struct {
				Undisclosed bool   `json:"undisclosed"`
				DiscloseAt  string `json:"disclose_at"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/findings", &row)
		if len(row.Items) != 1 || row.Items[0].Undisclosed {
			t.Fatalf("a disclosed finding reads as undisclosed: %+v", row.Items)
		}

		// The same finding, embargoed.
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Set("disclose_at = ?", "2027-01-31").
			Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		var after struct {
			Items []struct {
				Undisclosed bool   `json:"undisclosed"`
				DiscloseAt  string `json:"disclose_at"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/findings", &after)
		if len(after.Items) != 1 || !after.Items[0].Undisclosed {
			t.Fatalf("an embargoed finding does not say so on the row: %+v", after.Items)
		}
		if after.Items[0].DiscloseAt == "" {
			t.Error("the row does not carry the date the embargo ends")
		}

		// And the finding itself says it unmissably, which is what the row's
		// chip is only the secondary signal for.
		var detail struct {
			Undisclosed bool   `json:"undisclosed"`
			DiscloseAt  string `json:"disclose_at"`
		}
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &detail)
		if !detail.Undisclosed || detail.DiscloseAt == "" {
			t.Errorf("the finding does not say it is undisclosed: %+v", detail)
		}
	})
}

func TestAnEmbargoIsSaidBeforeItsDateNotOnIt(t *testing.T) {
	// The date arriving is the last moment to act rather than the first
	// useful warning, and an approver who touches disclosure a few times a
	// year has no reason to open the screen that would have told them.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		// Embargoed, with the date a week out — inside the default lead time
		// and not yet arrived.
		soon := time.Now().UTC().AddDate(0, 0, 7).Format(time.DateOnly)
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Set("disclose_at = ?", soon).
			Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		// Held by somebody: these go to administrators and to whoever
		// holds the work, which is who can act on it.
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/components/libnl-3-200/assignment",
			`{"person":"private-triage"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}

		coming := r.Alerts(t, "private-triage", "disclosure-near")
		if len(coming) != 1 {
			t.Fatalf("an embargo a week out raised %d notices: %v", len(coming), coming)
		}
		// It says the thing somebody has to act on, which is that arranging an
		// extension takes a second person and therefore takes time.
		if !httpapitest.Contains(coming[0], "second person") {
			t.Errorf("the notice does not say what has to be arranged: %q", coming[0])
		}
		// And it is not also being reported as arrived, which would be one
		// thing said twice.
		if arrived := r.Alerts(t, "private-triage", "disclosure-due"); len(arrived) != 0 {
			t.Errorf("an embargo that has not arrived is reported as arrived: %v", arrived)
		}

		// Somebody who may not read undisclosed work hears nothing at all,
		// however much else they hold.
		if told := r.Alerts(t, "triager", "disclosure-near"); len(told) != 0 {
			t.Errorf("somebody who may not read undisclosed work was told: %v", told)
		}

		// Once the date passes, the coming notice clears and the arrived one
		// opens. Two conditions, because they clear differently.
		past := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set("disclose_at = ?", past).Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if coming := r.Alerts(t, "private-triage", "disclosure-near"); len(coming) != 0 {
			t.Errorf("after the date the notice still says it is coming: %v", coming)
		}
		if arrived := r.Alerts(t, "private-triage", "disclosure-due"); len(arrived) != 1 {
			t.Errorf("after the date it raised %d arrived notices", len(arrived))
		}
	})
}
