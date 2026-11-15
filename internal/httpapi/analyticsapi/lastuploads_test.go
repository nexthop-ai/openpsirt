// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// TestTheLastUploadsListSaysWhenAndWhyAnUploadWasLastRefused pins the three
// moments and words a build's row carries: when a scan last arrived, when an
// upload was last turned away, and what its producer was told.
func TestTheLastUploadsListSaysWhenAndWhyAnUploadWasLastRefused(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		before := time.Now().UTC().Truncate(time.Second)
		const why = "the upload could not be read"
		if err := ingest.NewStore(r.DB.DB).Refused(t.Context(), access.Everything("a test"),
			ingest.Refusal{BuildID: r.BuildOf(t, httpapitest.SeededBuild), Reason: why}); err != nil {
			t.Fatal(err)
		}
		var got struct {
			Items []struct {
				Product        string `json:"product"`
				BranchOrTag    string `json:"branch_or_tag"`
				Variant        string `json:"variant"`
				LastReceivedAt string `json:"last_received_at"`
				LastRefusedAt  string `json:"last_refused_at"`
				RefusedBecause string `json:"refused_because"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/last-uploads", &got)
		found := false
		for _, row := range got.Items {
			if row.Product != "mine" || row.BranchOrTag != "master" || row.Variant != "broadcom" {
				if row.LastRefusedAt != "" || row.RefusedBecause != "" {
					t.Errorf("a build nothing was refused against reports a refusal: %+v", row)
				}
				continue
			}
			found = true
			if _, err := time.Parse(time.RFC3339, row.LastReceivedAt); err != nil {
				t.Errorf("the scanned build says it last received a scan at %q", row.LastReceivedAt)
			}
			refused, err := time.Parse(time.RFC3339, row.LastRefusedAt)
			if err != nil || refused.Before(before) {
				t.Errorf("the build says it was last refused at %q, want a moment since %s",
					row.LastRefusedAt, before.Format(time.RFC3339))
			}
			if row.RefusedBecause != why {
				t.Errorf("the build says it was refused because %q, want %q", row.RefusedBecause, why)
			}
		}
		if !found {
			t.Fatalf("the list holds no row for the seeded build: %+v", got.Items)
		}
	})
}
