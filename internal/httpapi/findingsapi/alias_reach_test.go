// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A name is identity deployment-wide, so recording one asks for triage in
// every product the issue is open in. Triage in the product the path names is
// not enough, and the refusal is the plain one: it does not name the product
// the caller cannot see.
//
// The issue is one a scan reported, so once triage is held everywhere the
// request goes on to the next rule and is refused for that: only a flaw
// recorded here takes a hand-typed name. That second refusal is what shows the
// first one was the triage check.
//
// Verified by deleting the loop over reaches in triagesEverywhere: the first
// assertion then answers 422, the scanner-issue refusal.
func TestRecordingAnotherNameNeedsTriageInEveryProductTheIssueIsOpenIn(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		r.AlsoScannedInto(t, "theirs", "master", "mellanox")
		const at = "/v1/products/mine/issues/CVE-2026-9999/aliases/GHSA-2c4j-5f6m-7q8r"

		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPut, at, "")
		httpapitest.RefusedWith(t, got, http.StatusForbidden)
		if strings.Contains(strings.ToLower(got.Body.String()), "theirs") {
			t.Errorf("the refusal names the product the caller cannot see: %s", got.Body.String())
		}
		var detail struct {
			Aliases []string `json:"aliases"`
		}
		httpapitest.Read(t, r, "private-triage", httpapitest.FindingAt("CVE-2026-9999"), &detail)
		if slices.Contains(detail.Aliases, "GHSA-2c4j-5f6m-7q8r") {
			t.Fatalf("a refused name was recorded: %v", detail.Aliases)
		}

		// Triage in the other product too, and the same request passes the
		// triage check and meets the rule about scanner issues.
		ctx := t.Context()
		rights := access.NewStore(r.DB.DB)
		who, err := rights.ByIdentity(ctx, "private-triage")
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, who.ID, theirs.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		both := httpapitest.AsPerson(t, r, "private-triage", http.MethodPut, at, "")
		httpapitest.RefusedWith(t, both, http.StatusUnprocessableEntity)
		if !strings.Contains(both.Body.String(), "only on a flaw recorded here") {
			t.Errorf("triage in both products was refused for something else: %s", both.Body.String())
		}
	})
}
