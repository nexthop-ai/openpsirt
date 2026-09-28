// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

// A name is identity deployment-wide, so recording one asks for triage in
// every product the issue is open in. Triage in the product the path names is
// not enough, and the refusal is the plain one: it does not name the product
// the caller cannot see.
//
// Verified by deleting the loop over reaches in triagesEverywhere: the name is
// then recorded and the first assertion answers 204.
func TestRecordingAnotherNameNeedsTriageInEveryProductTheIssueIsOpenIn(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		r.alsoScannedInto(t, "theirs", "master", "mellanox")
		const at = "/v1/products/mine/issues/CVE-2026-9999/aliases/GHSA-AAAA-BBBB-CCCC"

		got := asPerson(t, r, "private-triage", http.MethodPut, at, "")
		refusedWith(t, got, http.StatusForbidden)
		if strings.Contains(strings.ToLower(got.Body.String()), "theirs") {
			t.Errorf("the refusal names the product the caller cannot see: %s", got.Body.String())
		}
		var detail struct {
			Aliases []string `json:"aliases"`
		}
		read(t, r, "private-triage", findingAt("CVE-2026-9999"), &detail)
		if slices.Contains(detail.Aliases, "GHSA-AAAA-BBBB-CCCC") {
			t.Fatalf("a refused name was recorded: %v", detail.Aliases)
		}

		// Triage in the other product too, and the same request is recorded.
		ctx := t.Context()
		rights := access.NewStore(r.db.DB)
		who, err := rights.ByIdentity(ctx, "private-triage")
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := catalog.NewStore(r.db.DB).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, who.ID, theirs.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		if got := asPerson(t, r, "private-triage", http.MethodPut, at, ""); got.Code != http.StatusNoContent {
			t.Fatalf("triage in both products answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "private-triage", findingAt("CVE-2026-9999"), &detail)
		if !slices.Contains(detail.Aliases, "GHSA-AAAA-BBBB-CCCC") {
			t.Errorf("the name is not recorded: %v", detail.Aliases)
		}
	})
}
