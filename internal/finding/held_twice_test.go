// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// A place open under two names that merge is one finding held twice. The one
// open longer stays and the other closes as invalid. Where only the one that
// closes was assigned, the one that stays takes its assignment, so the work
// stays in the queue it was in; where both were, the one that stays keeps its
// own.
func TestAMergeCarriesTheAssignmentOfAPlaceHeldTwice(t *testing.T) {
	const other = "GHSA-aaaa-bbbb-cccc"
	for _, c := range []struct {
		name string
		// keeps is who holds the place under the name kept before the
		// merge, nil where nobody does.
		keeps *int64
	}{
		{"only the place that closes was assigned", nil},
		{"both places were assigned", ptr(int64(8))},
	} {
		t.Run(c.name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				ctx := t.Context()
				f.shipped(t, twoConsumers())
				// The other name first, so its places are the ones open
				// longer and the ones kept.
				f.applied(t, found(other, libnl))
				f.applied(t, found(other, libnl), found("CVE-2026-7001", libnl))
				assigner := f.holding(t, access.PublicTriage, access.Assigner)
				component := f.open(t)[0].ComponentID
				if c.keeps != nil {
					if _, _, err := f.store.Assign(ctx, assigner, f.target, f.issueID(t, other),
						component, c.keeps, nil); err != nil {
						t.Fatal(err)
					}
				}
				closing := f.issueID(t, "CVE-2026-7001")
				if moved, _, err := f.store.Assign(ctx, assigner, f.target, closing,
					component, ptr(int64(7)), nil); err != nil || moved != 2 {
					t.Fatalf("assigning the place that closes moved %d: %v", moved, err)
				}
				var given *time.Time
				for _, row := range f.open(t) {
					if row.VulnerabilityID == closing {
						given = row.AssignedAt
					}
				}
				if given == nil {
					t.Fatal("the assignment recorded no moment")
				}

				f.applied(t, found("CVE-2026-7001", libnl, other))

				open, closed := 0, 0
				for _, row := range f.every(t) {
					if row.ClosedAt != nil {
						closed++
						if row.ClosedBecause != finding.Invalid {
							t.Errorf("a place held twice closed as %q, want invalid", row.ClosedBecause)
						}
						continue
					}
					open++
					want, wantAt := int64(7), given
					if c.keeps != nil {
						want, wantAt = *c.keeps, nil
					}
					if row.AssignedTo == nil {
						t.Errorf("nobody holds the place that stays, want %d", want)
					} else if *row.AssignedTo != want {
						t.Errorf("the place that stays is held by %d, want %d", *row.AssignedTo, want)
					}
					if wantAt != nil && (row.AssignedAt == nil || !row.AssignedAt.Equal(*wantAt)) {
						t.Errorf("the place that stays was assigned at %v, want %v", row.AssignedAt, *wantAt)
					}
				}
				if open != 2 || closed != 2 {
					t.Fatalf("after the merge %d places are open and %d closed, want 2 and 2", open, closed)
				}
			})
		})
	}
}
