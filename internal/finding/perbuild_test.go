// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// One issue open in more builds than one statement joins, so the reads that
// group each build on its own nest their branches: every one of them still
// counts it once, across every build.
func TestWorkInMoreBuildsThanOneStatementJoinsIsCountedOnce(t *testing.T) {
	const builds = 55
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		for i := 1; i < builds; i++ {
			other := f.anotherVariant(t, fmt.Sprintf("variant-%02d", i))
			f.shippedTo(t, other, twoConsumers())
			if _, err := f.store.Apply(ctx, other, f.runOn(t, other),
				[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
				t.Fatal(err)
			}
		}
		who := f.holding(t, access.PublicRead, access.PublicTriage, access.Assigner)

		work, total, err := f.store.Unassigned(ctx, who, finding.Scope{}, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(work) != 1 {
			t.Fatalf("one issue in %d builds is %d items nobody holds: %+v", builds, total, work)
		}
		if work[0].Builds != builds {
			t.Errorf("the item covers %d builds, want %d", work[0].Builds, builds)
		}

		rows, whole, err := f.store.HowItStands(ctx, who, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if whole.Open != 1 || whole.Undecided != 1 {
			t.Errorf("the product holds %d open and %d undecided, want 1 and 1", whole.Open, whole.Undecided)
		}
		if len(rows) != builds {
			t.Errorf("the overview has %d build rows, want %d", len(rows), builds)
		}

		now := time.Now().UTC()
		read, err := f.store.Remediation(ctx, who, finding.Scope{}, now.Add(-90*24*time.Hour), now)
		if err != nil {
			t.Fatal(err)
		}
		open := 0
		for _, bucket := range read.Aging {
			open += bucket.Open
		}
		if open != 1 {
			t.Errorf("the aging buckets hold %d issues, want 1: %+v", open, read.Aging)
		}
	})
}
