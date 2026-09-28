// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// An unrated flaw somebody recorded reads as not rated on both lists.
//
// The list within a product and the list across products fill one row shape
// from two statements, and a column only one of them selects is left at zero
// in the other. Here the column is how many of a group's places a person
// recorded, which is what tells "nobody has rated it" apart from the reasons a
// scanner's finding carries no deadline.
func TestAnUnratedRecordedFlawReadsAsNotRatedAcrossProducts(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		_, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name,
			Summary: "The management socket accepts a request nobody authenticated.",
			Told:    finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		lists := map[string]func() ([]finding.Group, error){
			"within the product": func() ([]finding.Group, error) {
				groups, _, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{})
				return groups, err
			},
			"across products": func() ([]finding.Group, error) {
				groups, _, err := f.store.Anywhere(ctx, who, 50, 0, finding.Filter{})
				return groups, err
			},
		}
		for name, list := range lists {
			groups, err := list()
			if err != nil {
				t.Fatal(err)
			}
			saw := false
			for _, group := range groups {
				if group.Vulnerability != identifier {
					continue
				}
				saw = true
				if group.NoDeadline != finding.NotRated {
					t.Errorf("%s, an unrated recorded flaw is listed as %q, want %q",
						name, group.NoDeadline, finding.NotRated)
				}
			}
			if !saw {
				t.Errorf("%s, %s is not in the list", name, identifier)
			}
		}
	})
}
