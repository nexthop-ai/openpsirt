// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestANameIsTypedOnlyOntoAFlawRecordedHereAndInAShapeASchemeIssues(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		minted := r.Embargoed(t)

		// A scanner's issue is named by the scans that report it.
		if code := r.Alias(t, http.MethodPut, "CVE-2026-9999", "GHSA-2c4j-5f6m-7q8r"); code != http.StatusUnprocessableEntity {
			t.Errorf("a name typed onto an issue a scan reported answered %d, want 422", code)
		}
		for _, name := range []string{"CVE-27-1", "GHSA-xxxx-yyyy-zzzz", "OSV-2027-1"} {
			if code := r.Alias(t, http.MethodPut, minted, name); code != http.StatusUnprocessableEntity {
				t.Errorf("%s answered %d, want 422", name, code)
			}
		}
		for _, name := range []string{"GHSA-2c4j-5f6m-7q8r", "cve-2027-0001"} {
			if code := r.Alias(t, http.MethodPut, minted, name); code != http.StatusNoContent {
				t.Errorf("%s answered %d, want 204", name, code)
			}
		}
	})
}

func TestANameRecordedByHandIsRemovedAndTheFiledUnderNameIsNot(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		minted := r.Embargoed(t)
		const typed = "GHSA-2C4J-5F6M-7Q8R"
		if code := r.Alias(t, http.MethodPut, minted, typed); code != http.StatusNoContent {
			t.Fatalf("recording a name answered %d", code)
		}
		var detail struct {
			Aliases       []string `json:"aliases"`
			AliasesByHand []string `json:"aliases_by_hand"`
		}
		httpapitest.Read(t, r, "private-triage", httpapitest.FindingAt(minted), &detail)
		if !slices.Contains(detail.AliasesByHand, typed) {
			t.Fatalf("a name recorded by hand is not offered for removal: %+v", detail)
		}

		// The name it is filed under is never removed.
		if code := r.Alias(t, http.MethodDelete, minted, minted); code != http.StatusUnprocessableEntity {
			t.Errorf("removing the filed-under name answered %d, want 422", code)
		}
		if code := r.Alias(t, http.MethodDelete, minted, "GHSA-3c4j-5f6m-7q8r"); code != http.StatusNotFound {
			t.Errorf("removing a name it does not go by answered %d, want 404", code)
		}
		if code := r.Alias(t, http.MethodDelete, minted, typed); code != http.StatusOK {
			t.Fatalf("removing a name recorded by hand answered %d", code)
		}
		detail.Aliases, detail.AliasesByHand = nil, nil
		httpapitest.Read(t, r, "private-triage", httpapitest.FindingAt(minted), &detail)
		if slices.Contains(detail.Aliases, typed) {
			t.Errorf("the name is still carried after its removal: %+v", detail)
		}

		// The next scan reporting it opens an issue of its own.
		ids, err := finding.NewVulnerabilities(r.DB.DB).Intern(t.Context(),
			[]finding.Named{{Identifier: typed, Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue, err := finding.NewVulnerabilities(r.DB.DB).ByName(t.Context(), minted)
		if err != nil {
			t.Fatal(err)
		}
		if ids[typed] == issue {
			t.Error("a scan reporting a removed name still resolves to the issue it was removed from")
		}
	})
}

func TestANameAScanReportedIsNotRemovedByHand(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		minted := r.Embargoed(t)
		if code := r.Alias(t, http.MethodPut, minted, "CVE-2027-0001"); code != http.StatusNoContent {
			t.Fatalf("recording a CVE answered %d", code)
		}
		// A scan reporting the CVE carries a second name, which joins it.
		const reported = "GHSA-4c4j-5f6m-7q8r"
		if _, err := finding.NewVulnerabilities(r.DB.DB).Intern(t.Context(), []finding.Named{{
			Identifier: "CVE-2027-0001", Aliases: []string{reported}, Severity: "high",
		}}); err != nil {
			t.Fatal(err)
		}
		if code := r.Alias(t, http.MethodDelete, "CVE-2027-0001", reported); code != http.StatusUnprocessableEntity {
			t.Errorf("removing a name a scan reported answered %d, want 422", code)
		}
	})
}

func TestAMistypedCVEIsRemovedAndTheFlawRefiledUnderItsOwnReference(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		minted := r.Embargoed(t)
		const typo = "CVE-2027-9001"
		if code := r.Alias(t, http.MethodPut, minted, typo); code != http.StatusNoContent {
			t.Fatalf("recording a CVE answered %d", code)
		}
		var detail struct {
			Vulnerability string   `json:"vulnerability"`
			AliasesByHand []string `json:"aliases_by_hand"`
		}
		httpapitest.Read(t, r, "private-triage", httpapitest.FindingAt(minted), &detail)
		if detail.Vulnerability != typo {
			t.Fatalf("the flaw is filed under %q, want the CVE typed", detail.Vulnerability)
		}
		if !slices.Contains(detail.AliasesByHand, typo) {
			t.Errorf("the filed-under CVE typed by hand is not offered for removal: %v", detail.AliasesByHand)
		}

		var before httpapitest.Changed
		httpapitest.Read(t, r, "admin", "/v1/administration/changes?limit=1", &before)
		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodDelete,
			fmt.Sprintf("/v1/products/mine/issues/%s/aliases/%s", typo, typo), "")
		if got.Code != http.StatusOK {
			t.Fatalf("removing the filed-under CVE typed by hand answered %d: %s", got.Code, got.Body.String())
		}
		var removed struct {
			FiledUnder string `json:"filed_under"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &removed); err != nil {
			t.Fatal(err)
		}
		if removed.FiledUnder != minted {
			t.Errorf("the answer says it is filed under %q, want %q", removed.FiledUnder, minted)
		}
		detail.Vulnerability = ""
		httpapitest.Read(t, r, "private-triage", httpapitest.FindingAt(minted), &detail)
		if detail.Vulnerability != minted {
			t.Errorf("after the removal the flaw is filed under %q, want its own reference %q",
				detail.Vulnerability, minted)
		}
		var after httpapitest.Changed
		httpapitest.Read(t, r, "admin", "/v1/administration/changes?limit=1", &after)
		if after.Total != before.Total+1 || len(after.Items) == 0 || after.Items[0].Kind != "alias" ||
			after.Items[0].Was != typo {
			t.Errorf("the removal left %d rows, newest %+v", after.Total-before.Total, after.Items)
		}
	})
}
