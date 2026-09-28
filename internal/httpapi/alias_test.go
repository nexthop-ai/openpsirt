// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// alias records or removes another name for an issue, answering the status.
func (r *reach) alias(t *testing.T, method, issue, name string) int {
	t.Helper()
	got := asPerson(t, r, "private-triage", method,
		fmt.Sprintf("/v1/products/mine/issues/%s/aliases/%s", issue, name), "")
	return got.Code
}

func TestANameIsTypedOnlyOntoAFlawRecordedHereAndInAShapeASchemeIssues(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		minted := r.embargoed(t)

		// A scanner's issue is named by the scans that report it.
		if code := r.alias(t, http.MethodPut, "CVE-2026-9999", "GHSA-2c4j-5f6m-7q8r"); code != http.StatusUnprocessableEntity {
			t.Errorf("a name typed onto an issue a scan reported answered %d, want 422", code)
		}
		for _, name := range []string{"CVE-27-1", "GHSA-xxxx-yyyy-zzzz", "OSV-2027-1"} {
			if code := r.alias(t, http.MethodPut, minted, name); code != http.StatusUnprocessableEntity {
				t.Errorf("%s answered %d, want 422", name, code)
			}
		}
		for _, name := range []string{"GHSA-2c4j-5f6m-7q8r", "cve-2027-0001"} {
			if code := r.alias(t, http.MethodPut, minted, name); code != http.StatusNoContent {
				t.Errorf("%s answered %d, want 204", name, code)
			}
		}
	})
}

func TestANameRecordedByHandIsRemovedAndTheFiledUnderNameIsNot(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		minted := r.embargoed(t)
		const typed = "GHSA-2C4J-5F6M-7Q8R"
		if code := r.alias(t, http.MethodPut, minted, typed); code != http.StatusNoContent {
			t.Fatalf("recording a name answered %d", code)
		}
		var detail struct {
			Aliases       []string `json:"aliases"`
			AliasesByHand []string `json:"aliases_by_hand"`
		}
		read(t, r, "private-triage", findingAt(minted), &detail)
		if !slices.Contains(detail.AliasesByHand, typed) {
			t.Fatalf("a name recorded by hand is not offered for removal: %+v", detail)
		}

		// The name it is filed under is never removed.
		if code := r.alias(t, http.MethodDelete, minted, minted); code != http.StatusUnprocessableEntity {
			t.Errorf("removing the filed-under name answered %d, want 422", code)
		}
		if code := r.alias(t, http.MethodDelete, minted, "GHSA-3c4j-5f6m-7q8r"); code != http.StatusNotFound {
			t.Errorf("removing a name it does not go by answered %d, want 404", code)
		}
		if code := r.alias(t, http.MethodDelete, minted, typed); code != http.StatusNoContent {
			t.Fatalf("removing a name recorded by hand answered %d", code)
		}
		detail.Aliases, detail.AliasesByHand = nil, nil
		read(t, r, "private-triage", findingAt(minted), &detail)
		if slices.Contains(detail.Aliases, typed) {
			t.Errorf("the name is still carried after its removal: %+v", detail)
		}

		// The next scan reporting it opens an issue of its own.
		ids, err := finding.NewVulnerabilities(r.db.DB).Intern(t.Context(),
			[]finding.Named{{Identifier: typed, Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue, err := finding.NewVulnerabilities(r.db.DB).ByName(t.Context(), minted)
		if err != nil {
			t.Fatal(err)
		}
		if ids[typed] == issue {
			t.Error("a scan reporting a removed name still resolves to the issue it was removed from")
		}
	})
}

func TestANameAScanReportedIsNotRemovedByHand(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		minted := r.embargoed(t)
		if code := r.alias(t, http.MethodPut, minted, "CVE-2027-0001"); code != http.StatusNoContent {
			t.Fatalf("recording a CVE answered %d", code)
		}
		// A scan reporting the CVE carries a second name, which joins it.
		const reported = "GHSA-4c4j-5f6m-7q8r"
		if _, err := finding.NewVulnerabilities(r.db.DB).Intern(t.Context(), []finding.Named{{
			Identifier: "CVE-2027-0001", Aliases: []string{reported}, Severity: "high",
		}}); err != nil {
			t.Fatal(err)
		}
		if code := r.alias(t, http.MethodDelete, "CVE-2027-0001", reported); code != http.StatusUnprocessableEntity {
			t.Errorf("removing a name a scan reported answered %d, want 422", code)
		}
		// The CVE was typed by hand and the issue is now filed under it,
		// which is the one name never removed.
		if code := r.alias(t, http.MethodDelete, "CVE-2027-0001", "CVE-2027-0001"); code != http.StatusUnprocessableEntity {
			t.Errorf("removing the filed-under name, recorded by hand, answered %d, want 422", code)
		}
	})
}
