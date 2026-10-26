// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package supplier_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAFeedRecordsWhatArrivedAsArrivingByItself(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		taken := advisory("EL-2026-0050", "libnl-3-200", "3.7.1", "CVE-2026-5050")
		p.publishes("/2026/EL-50.json", "2026-09-20T00:00:00Z", taken)
		// About nothing this product ships, so there is nothing to list.
		p.publishes("/2026/EL-51.json", "2026-09-21T00:00:00Z",
			advisory("EL-2026-0051", "some-other-package", "9.9.9", "CVE-2026-5051"))
		// Withdrawn: nothing arrived.
		p.publishes("/2026/EL-52.json", "2026-09-22T00:00:00Z", "")
		p.failing["/2026/EL-52.json"] = http.StatusNotFound
		// Arrived, and refused once it was read.
		p.publishes("/2026/EL-53.json", "2026-09-23T00:00:00Z", `{"document":`)
		mismatched := advisory("EL-2026-0054", "libnl-3-200", "3.7.1", "CVE-2026-5054")
		// Read first, while the pass still looks for a digest beside each.
		p.publishes("/2026/EL-54.json", "2026-09-19T00:00:00Z", mismatched)
		p.documents["/2026/EL-54.json.sha256"] = sha256Of(mismatched+" ", "EL-54.json")

		source := from(t, f, p)
		took, err := fetching(t, f, p).From(ctx, f.by, source)
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 2 || took.Refused != 2 || took.Mismatched != 1 {
			t.Fatalf("the pass read %+v; want two read, two refused and one mismatched", took)
		}

		held, total, err := finding.NewStore(f.db.DB).Uploads(ctx, access.Everything("the test"),
			f.product, finding.FromAdvisory, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 3 || len(held) != 3 {
			t.Fatalf("the uploads read %+v of %d; want the advisory about this product and the two "+
				"refused once they arrived", held, total)
		}
		malformed, recorded, wrongSum := held[0], held[1], held[2]
		for name, u := range map[string]finding.Upload{"mismatched": wrongSum, "malformed": malformed, "taken": recorded} {
			if u.FeedID == nil || *u.FeedID != source.ID || u.Credential != nil || u.Feed != "Example Linux" {
				t.Errorf("the %s one arrived by %v and %v named %q; want the feed alone",
					name, u.FeedID, u.Credential, u.Feed)
			}
		}
		if malformed.Status != finding.UploadTurnedAway || malformed.Reason == nil ||
			malformed.Document != p.server.URL+"/2026/EL-53.json" || malformed.Publisher != "" {
			t.Errorf("the malformed document reads %+v", malformed)
		}
		// Parsed before its digest was compared, so it says whose it is.
		if wrongSum.Status != finding.UploadTurnedAway || wrongSum.Identifier != "EL-2026-0054" ||
			wrongSum.Publisher == "" || wrongSum.Digest == nil || *wrongSum.Digest != sha256Hex(mismatched) {
			t.Errorf("the document mismatching its digest reads %+v", wrongSum)
		}
		// The digest is over what arrived, as an upload's is.
		if recorded.Status != finding.UploadTaken || recorded.Identifier != "EL-2026-0050" ||
			recorded.Recorded != 1 || !recorded.Current() ||
			recorded.Digest == nil || *recorded.Digest != sha256Hex(taken) {
			t.Errorf("the advisory reads %+v", recorded)
		}
	})
}

func sha256Hex(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
