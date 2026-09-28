// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"strings"
	"testing"
)

// The routes that take many issue names at once answer a name filed only
// where the caller may not look exactly as they answer a name nobody filed.
// Answered differently, one guess at a time enumerates which embargoed issues
// the deployment holds.

func TestAManyNamedClaimAnswersAnUnseenIssueAsAnUnknownOne(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		r.alsoHolds(t, "theirs", "master", "mellanox", "CVE-2027-4242")
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/linux-image/decisions"
		claim := func(name string) (int, string) {
			got := asPerson(t, r, "triager", http.MethodPost, at,
				`{"vulnerabilities":["CVE-2026-9999","`+name+`"],"outcome":"wont-fix",`+
					`"selected_by":"the drivers","reasoning":"Not built for this image."}`)
			return got.Code, got.Body.String()
		}
		held, heldSaid := claim("CVE-2027-4242")
		nobody, nobodySaid := claim("CVE-2027-0000")
		if held != http.StatusNotFound || nobody != http.StatusNotFound {
			t.Fatalf("an unseen name answered %d and an unknown one %d, want 404 for both", held, nobody)
		}
		if strings.ReplaceAll(heldSaid, "CVE-2027-4242", "X") !=
			strings.ReplaceAll(nobodySaid, "CVE-2027-0000", "X") {
			t.Errorf("an unseen name and an unknown one answered differently:\n%s\n%s",
				heldSaid, nobodySaid)
		}
	})
}

func TestAssigningPickedRowsAnswersAnUnseenIssueAsAnUnknownOne(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		r.alsoHolds(t, "theirs", "master", "mellanox", "CVE-2027-4242")
		assign := func(name string) (int, string) {
			got := asPerson(t, r, "triager", http.MethodPost, matchingAt+"?planned=either",
				`{"person":"triager","only":[{"vulnerability":"`+name+`","fold":"linux-image"}]}`)
			return got.Code, got.Body.String()
		}
		held, heldSaid := assign("CVE-2027-4242")
		nobody, nobodySaid := assign("CVE-2027-0000")
		if held != nobody || strings.ReplaceAll(heldSaid, "CVE-2027-4242", "X") !=
			strings.ReplaceAll(nobodySaid, "CVE-2027-0000", "X") {
			t.Errorf("an unseen name answered %d %s and an unknown one %d %s",
				held, heldSaid, nobody, nobodySaid)
		}
		if nobody != http.StatusNotFound {
			t.Errorf("an unknown name answered %d, want 404", nobody)
		}
	})
}
