// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestTheListKeepsToTheReleasesWorkCanLandIn(t *testing.T) {
	// Thirty-odd filters and none about the release itself, so a work list
	// carried releases no work will ever land in: a tag was built once and is
	// what somebody received, and a release past end-of-life is not being
	// rebuilt either. Two questions rather than one, because a tag can be in
	// support and a branch can be past its date.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		// The same issue in a tag, and in a branch that has gone out of
		// support. Three builds, one of each kind of answer.
		tag := f.anotherBuild(t, "v2.4.1")
		f.shippedTo(t, tag, through(libnl))
		if _, err := f.store.Apply(ctx, tag, f.runOn(t, tag), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		retired := f.anotherBranch(t, "release-1.x")
		f.shippedTo(t, retired, through(libnl))
		if _, err := f.store.Apply(ctx, retired, f.runOn(t, retired), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		cat := catalog.NewStore(f.db.DB)
		gone, err := cat.StreamByName(ctx, f.productID, "release-1.x")
		if err != nil {
			t.Fatal(err)
		}
		yesterday := time.Now().UTC().AddDate(0, 0, -1)
		if err := cat.SetStreamEndOfLife(ctx, gone.ID, &yesterday); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicRead)
		places := func(only finding.Workable) int {
			t.Helper()
			rows, _, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0,
				finding.Filter{Workable: only})
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) == 0 {
				return 0
			}
			return rows[0].Places
		}

		both := []string{finding.OnBranch, finding.OnTag}
		either := []string{finding.InSupport, finding.PastEndOfLife}
		for _, each := range []struct {
			what string
			only finding.Workable
			want int
		}{
			// The screen's own question unless told otherwise: the branch
			// still in support, and neither of the other two.
			{"the default", finding.Working(nil, nil), 1},
			{"tags as well", finding.Working(both, nil), 2},
			{"tags alone", finding.Working([]string{finding.OnTag}, nil), 1},
			{"what is out of support", finding.Working(nil, []string{finding.PastEndOfLife}), 1},
			{"either state of support", finding.Working(nil, either), 2},
			// Separable: both widened is every build, and each widened alone
			// is not.
			{"everything", finding.Working(both, either), 3},
			// The zero value narrows nothing, so a caller that was never
			// asked answers about all of it.
			{"nobody asked", finding.Workable{}, 3},
		} {
			if got := places(each.only); got != each.want {
				t.Errorf("%s counts %d places, want %d", each.what, got, each.want)
			}
		}
	})
}
