// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// An issue page names what merged into the issue. A record merged in from a
// product the reader may not read is named by its minted identifier, which is
// one of the names withheld from them, so the page names no merge for them.
func TestAnIssuePageNamesNoMergeOfARecordOutOfReach(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.Scanned(t)
		r.AlsoScannedInto(t, "theirs", "master", "mellanox")
		db := r.DB.DB
		issue, err := finding.NewVulnerabilities(db).ByName(ctx, "CVE-2026-9999")
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		absorbed := &finding.Vulnerability{
			Identifier: "THEIRS-2026-1", IdentifierFolded: finding.FoldIdentifier("THEIRS-2026-1"),
			FirstSeenAt: at,
		}
		if _, err := db.NewInsert().Model(absorbed).Value("issue_id", "?", issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.NewInsert().Model(&finding.Merge{
			AbsorbedID: absorbed.ID, KeptID: issue, Named: "CVE-2026-9999 THEIRS-2026-1", MergedAt: at,
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		theirs := r.TargetOf(t, httpapitest.Build{Product: "theirs", Stream: "master", Variant: "mellanox"})
		var row finding.Finding
		if err := db.NewSelect().Model(&row).Where(`"target_id" = ?`, theirs).Limit(1).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		row.ID, row.Kind, row.Visibility = 0, finding.Entered, access.Private
		row.PlaceIdentity = finding.PlaceIdentity("recorded", "by-hand")
		if _, err := db.NewInsert().Model(&row).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		var page struct {
			Merged []struct {
				Vulnerability string `json:"vulnerability"`
			} `json:"merged"`
		}
		httpapitest.Read(t, r, "private", "/v1/issues/CVE-2026-9999", &page)
		if len(page.Merged) != 0 {
			t.Errorf("a reader of the other product alone was told of merges %+v", page.Merged)
		}

		rights := access.NewStore(db)
		who, err := rights.ByIdentity(ctx, "private")
		if err != nil {
			t.Fatal(err)
		}
		product, err := catalog.NewStore(db).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range []access.Role{access.PublicRead, access.PrivateRead} {
			if err := rights.GrantRole(ctx, who.ID, product.ID, role); err != nil {
				t.Fatal(err)
			}
		}
		page.Merged = nil
		httpapitest.Read(t, r, "private", "/v1/issues/CVE-2026-9999", &page)
		if len(page.Merged) != 1 || page.Merged[0].Vulnerability != "THEIRS-2026-1" {
			t.Errorf("a reader of both products was told of merges %+v, want the record's", page.Merged)
		}
	})
}
