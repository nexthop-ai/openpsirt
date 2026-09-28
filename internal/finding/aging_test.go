// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// An aging bucket says how much of it is undecided and how it splits by
// severity. A claim waiting for a second person answers nothing, so its issue
// is still undecided; an approved one stands. The split counts issues, so its
// parts sum to the bucket.
func TestAnAgingBucketSaysWhatIsUndecidedAndHowItSplitsBySeverity(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			{Issue: finding.Named{Identifier: "CVE-2026-1", Severity: "critical"}, Component: swss},
			{Issue: finding.Named{Identifier: "CVE-2026-2", Severity: "low"}, Component: libnl},
		}); err != nil {
			t.Fatal(err)
		}
		old := time.Now().UTC().Add(-120 * 24 * time.Hour)
		f.aged(t, "CVE-2026-1", old)
		f.aged(t, "CVE-2026-2", old)

		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "somebody@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-1"),
			finding.PlaceIdentity(swss.Name, ""), "approved", swss.Version, "agreed")
		// Waiting at every place the low issue sits, so that nothing but the
		// waiting is what leaves it undecided.
		for i, consumer := range []string{swss.Name, teamd.Name} {
			f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-2"),
				finding.PlaceIdentity(libnl.Name, consumer), "proposed", libnl.Version,
				[]string{"waiting-one", "waiting-two"}[i])
		}

		got, err := f.store.Remediation(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		var bucket *finding.Bucket
		for i := range got.Aging {
			if got.Aging[i].Label == "over three months" {
				bucket = &got.Aging[i]
			}
		}
		if bucket == nil {
			t.Fatalf("no bucket for over three months in %+v", got.Aging)
		}
		if bucket.Open != 2 {
			t.Fatalf("the bucket holds %d issues, want the 2 aged into it", bucket.Open)
		}
		if bucket.Undecided != 1 {
			t.Errorf("%d undecided, want 1: the waiting claim answers nothing and the approved one stands",
				bucket.Undecided)
		}
		if len(bucket.BySeverity) != 2 || bucket.BySeverity["critical"] != 1 || bucket.BySeverity["low"] != 1 {
			t.Errorf("by severity %v, want one critical and one low", bucket.BySeverity)
		}
	})
}
