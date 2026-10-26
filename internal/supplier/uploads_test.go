// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package supplier_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAFeedRecordsWhatItFetchedAndRefusedAsArrivingByItself(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-50.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0050", "libnl-3-200", "3.7.1", "CVE-2026-5050"))
		// About nothing this product ships, so there is nothing to list.
		p.publishes("/2026/EL-51.json", "2026-09-21T00:00:00Z",
			advisory("EL-2026-0051", "some-other-package", "9.9.9", "CVE-2026-5051"))
		p.publishes("/2026/EL-52.json", "2026-09-22T00:00:00Z", "")
		p.failing["/2026/EL-52.json"] = http.StatusNotFound

		source := from(t, f, p)
		took, err := fetching(t, f, p).From(ctx, f.by, source)
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 2 || took.Refused != 1 {
			t.Fatalf("the pass read %+v; want two documents read and one refused", took)
		}

		held, total, err := finding.NewStore(f.db.DB).Uploads(ctx, access.Everything("the test"),
			f.product, finding.FromAdvisory, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(held) != 2 {
			t.Fatalf("the uploads read %+v of %d; want the refusal and the one advisory about this product",
				held, total)
		}
		refused, taken := held[0], held[1]
		for name, u := range map[string]finding.Upload{"refused": refused, "taken": taken} {
			if u.FeedID == nil || *u.FeedID != source.ID || u.Credential != nil || u.Feed != "Example Linux" {
				t.Errorf("the %s one arrived by %v and %v named %q; want the feed alone",
					name, u.FeedID, u.Credential, u.Feed)
			}
		}
		if refused.Status != finding.UploadTurnedAway || refused.Reason == nil || *refused.Reason == "" ||
			refused.Document != p.server.URL+"/2026/EL-52.json" {
			t.Errorf("the withdrawn document reads %+v", refused)
		}
		if taken.Status != finding.UploadTaken || taken.Identifier != "EL-2026-0050" ||
			taken.Recorded != 1 || !taken.Current() {
			t.Errorf("the advisory reads %+v", taken)
		}
	})
}
