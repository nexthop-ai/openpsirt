// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package csaf_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/csaf"
)

// A description naming a key claims the trusted provider role and one naming
// none the provider role, and both describe the one feed in the same words,
// dated from the newest document.
func TestADescriptionClaimsTheRoleItsKeysEarn(t *testing.T) {
	newest := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	base := csaf.Description{
		Metadata: "https://p.example/m.json", Directory: "https://p.example/d/",
		Feed: "https://p.example/f.json", Name: "Example Networks", TLP: "WHITE",
		Publisher: csaf.Issuer{Category: "vendor", Name: "Example Networks", Namespace: "https://example.test"},
		Listed:    true, Newest: newest,
	}
	signed := base
	signed.Keys = []csaf.PublicKey{{Fingerprint: "ABCD", URL: "https://p.example/k/ABCD.asc"}}
	for _, tc := range []struct {
		name string
		d    csaf.Description
		role string
	}{{"unsigned", base, csaf.Provider}, {"signed", signed, csaf.TrustedProvider}} {
		got := csaf.Describe(tc.d)
		if got.Role != tc.role || len(got.PublicKeys) != len(tc.d.Keys) {
			t.Errorf("%s: role %q with %d keys, want %q with %d", tc.name, got.Role,
				len(got.PublicKeys), tc.role, len(tc.d.Keys))
		}
		feed := got.Distributions[0].ROLIE.Feeds[0]
		if feed.Summary != "Security documents Example Networks publishes, TLP:WHITE." ||
			feed.URL != tc.d.Feed || got.Distributions[0].DirectoryURL != tc.d.Directory {
			t.Errorf("%s: the feed is described as %+v in %+v", tc.name, feed, got.Distributions)
		}
		if got.LastUpdated != csaf.Stamp(newest) || got.CanonicalURL != tc.d.Metadata ||
			!got.Listed || got.Mirrored || got.Publisher != tc.d.Publisher {
			t.Errorf("%s: described as %+v", tc.name, got)
		}
	}
	if title := csaf.FeedTitle("Example Networks", "WHITE"); title != "Example Networks CSAF documents (TLP:WHITE)" {
		t.Errorf("the feed is titled %q", title)
	}
}
