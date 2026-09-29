// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAMergeKeepsTheListingDayOfTheIssueItAbsorbs(t *testing.T) {
	// The advisory's own record carried the listing day and the national
	// record did not. A report naming both merges them, and the issue that
	// stands keeps the day, so its findings count from it whichever record
	// they were filed under.
	each(t, func(t *testing.T, f *fixture) {
		day := daysAgo(20)
		v := finding.NewVulnerabilities(f.db.DB)
		if _, err := v.Intern(t.Context(), []finding.Named{
			{Identifier: "GHSA-aaaa-bbbb-cccc", Exploited: true, ExploitedOn: &day},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Intern(t.Context(), []finding.Named{
			{Identifier: "CVE-2026-7001", Exploited: true},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Intern(t.Context(), []finding.Named{
			{Identifier: "CVE-2026-7001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Exploited: true},
		}); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"CVE-2026-7001", "GHSA-aaaa-bbbb-cccc"} {
			if got := f.listedOn(t, name); !isAt(got, day) {
				t.Errorf("after the merge %s reads as listed on %v, want %s", name, got, day)
			}
		}
	})
}
