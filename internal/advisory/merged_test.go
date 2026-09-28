// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAnAdvisoryCoveringANameThatMergedCoversTheIssueThatStandsOnce(t *testing.T) {
	// Two flaws recorded apart turn out to be one, and a report naming both
	// merges them. An advisory that covered both names covers the one issue,
	// once, and is still generated from its findings and found by the name that
	// stands.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := f.recorded(t, f.master)
		second := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", first}, [2]string{"sonic", second})
		onlyMerged := f.covering(t, [2]string{"sonic", second})

		if _, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx, []finding.Named{
			{Identifier: first, Aliases: []string{second}},
		}); err != nil {
			t.Fatalf("merge the two: %v", err)
		}

		_, covered, err := f.store.Covers(ctx, f.who, named)
		if err != nil {
			t.Fatal(err)
		}
		if len(covered) != 1 || covered[0].Issue != first {
			t.Errorf("the advisory covers %+v, want %s once", covered, first)
		}
		if _, err := f.store.ForAdvisory(ctx, f.who, issuer, named); err != nil {
			t.Errorf("the advisory cannot be generated after the merge: %v", err)
		}
		// Found by the name that stands, including where only the merged
		// name was covered.
		found, _, err := f.store.List(ctx, f.who, advisory.Covering{Vulnerability: first}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, one := range found {
			names[one.Identifier] = true
		}
		if len(found) != 2 || !names[named] || !names[onlyMerged] {
			t.Errorf("a search by the name that stands finds %+v, want %s and %s",
				found, named, onlyMerged)
		}
	})
}
