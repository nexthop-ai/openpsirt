// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// throughOf reads the source package each open finding of an issue was
// matched through.
func throughOf(t *testing.T, f *fixture, issue string) []string {
	t.Helper()
	var through []*string
	if err := f.db.NewSelect().Table("finding").ColumnExpr(`"finding"."matched_through"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "finding"."vulnerability_id"`).
		Where(`"v"."identifier" = ?`, issue).
		Where(`"finding"."closed_at" IS NULL`).
		Scan(t.Context(), &through); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(through))
	for _, each := range through {
		if each == nil {
			out = append(out, "")
		} else {
			out = append(out, *each)
		}
	}
	return out
}

// filesOf reads the files an issue's record was last read as listing.
func filesOf(t *testing.T, f *fixture, issue string) []string {
	t.Helper()
	var id int64
	if err := f.db.NewSelect().Table("vulnerability").Column("id").
		Where(`"identifier" = ?`, issue).Scan(t.Context(), &id); err != nil {
		t.Fatal(err)
	}
	files, err := finding.ProgramFiles(t.Context(), f.db, []int64{id})
	if err != nil {
		t.Fatal(err)
	}
	return files[id]
}

func TestTheSourceAMatchWasMadeThroughIsKeptAndMoves(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		through := found("CVE-2024-26600", teamd)
		through.MatchedThrough = "linux"
		own := found("CVE-2023-52603", swss)
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{through, own}); err != nil {
			t.Fatal(err)
		}
		if got := throughOf(t, f, "CVE-2024-26600"); len(got) == 0 || got[0] != "linux" {
			t.Errorf("a match through the source reads as through %v, want linux", got)
		}
		if got := throughOf(t, f, "CVE-2023-52603"); len(got) == 0 || got[0] != "" {
			t.Errorf("a match on the package's own name reads as through %v, want none", got)
		}

		// The next scan matches the first on the package's own name, and the
		// open finding says so.
		through.MatchedThrough = ""
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{through, own}); err != nil {
			t.Fatal(err)
		}
		if got := throughOf(t, f, "CVE-2024-26600"); len(got) == 0 || got[0] != "" {
			t.Errorf("a match that moved to the package's own name still reads as through %v", got)
		}
	})
}

func TestTheFilesAnIssuesRecordListsAreKeptAsTheRecordLastSaid(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		listed := found("CVE-2024-26600", teamd)
		listed.RecordRead = true
		listed.RecordFiles = []string{"drivers/phy/ti/phy-omap-usb2.c", "drivers/phy/ti/phy-omap-usb2.c"}
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{listed}); err != nil {
			t.Fatal(err)
		}
		if got := filesOf(t, f, "CVE-2024-26600"); !slices.Equal(got, []string{"drivers/phy/ti/phy-omap-usb2.c"}) {
			t.Errorf("the issue lists %v, want the one file its record names", got)
		}

		// A run that read no records says nothing about the files.
		unread := found("CVE-2024-26600", teamd)
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{unread}); err != nil {
			t.Fatal(err)
		}
		if got := filesOf(t, f, "CVE-2024-26600"); len(got) != 1 {
			t.Errorf("a run reading no records left the issue listing %v", got)
		}

		// A record that lists none any more empties the list.
		emptied := found("CVE-2024-26600", teamd)
		emptied.RecordRead = true
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{emptied}); err != nil {
			t.Fatal(err)
		}
		if got := filesOf(t, f, "CVE-2024-26600"); len(got) != 0 {
			t.Errorf("a record listing nothing left the issue listing %v", got)
		}
	})
}
