// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestOneReportStandsForAnIssueAcrossTheNamesMergedIntoIt(t *testing.T) {
	// A report judged as one issue is the record of the issue it merges
	// into. A second report judged as that issue is a duplicate, whichever
	// name the first was judged under.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		kept := f.anIssueHere(t, who, "The management socket accepts a request nobody authenticated.")
		absorbed := f.anIssueHere(t, who, "The same flaw, found by another feed.")
		keptName, absorbedName := f.issues[0].Issue.Identifier, f.issues[1].Issue.Identifier

		first, err := f.store.Record(ctx, who, f.productID,
			finding.Claimed{Summary: "The management socket lets anybody in."})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.JudgeAsIssue(ctx, who, f.productID, first.Reference, absorbed); err != nil {
			t.Fatal(err)
		}
		if _, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx, []finding.Named{
			{Identifier: keptName, Aliases: []string{absorbedName}},
		}); err != nil {
			t.Fatalf("merge the two: %v", err)
		}

		second, err := f.store.Record(ctx, who, f.productID,
			finding.Claimed{Summary: "Somebody else says the same thing."})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.JudgeAsIssue(ctx, who, f.productID,
			second.Reference, kept); !errors.Is(err, finding.ErrIssueReported) {
			t.Errorf("a second report judged as the merged issue was answered %v", err)
		}
	})
}
