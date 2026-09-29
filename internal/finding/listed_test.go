// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// daysAgo is midnight UTC a number of days before today, the shape a catalog
// listing day is read in.
func daysAgo(n int) time.Time {
	return time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -n)
}

// listedOn reads the day an issue is stored as listed in the known-exploited
// catalog.
func (f *fixture) listedOn(t *testing.T, identifier string) *time.Time {
	t.Helper()
	var row finding.Vulnerability
	if err := f.db.DB.NewSelect().Model(&row).
		Where("id = ?", f.issueID(t, identifier)).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return row.ExploitedOn
}

// clockOf reads the one open finding of an issue in a build.
func (f *fixture) clockOf(t *testing.T, target int64, identifier string) finding.Finding {
	t.Helper()
	var rows []finding.Finding
	if err := f.db.DB.NewSelect().Model(&rows).
		Where("target_id = ?", target).
		Where("vulnerability_id = ?", f.issueID(t, identifier)).
		Where("closed_at IS NULL").
		Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d open findings of %s in build %d, want one", len(rows), identifier, target)
	}
	return rows[0]
}

// exploitedWindow is how long an exploited finding has, as this deployment is
// configured.
func (f *fixture) exploitedWindow(t *testing.T) time.Duration {
	t.Helper()
	windows, err := finding.LoadWindows(t.Context(), f.db.DB)
	if err != nil {
		t.Fatal(err)
	}
	return windows.Exploited
}

// listed is a report of an issue as exploited, listed in the catalog on a day
// or on none.
func listed(identifier string, on *time.Time) finding.Reported {
	one := found(identifier, swss)
	one.Issue.Exploited = true
	one.Issue.ExploitedOn = on
	return one
}

// isAt reports whether a date that may be absent is this moment.
func isAt(a *time.Time, b time.Time) bool { return a != nil && a.Equal(b) }

func TestAnIssueKeepsTheEarliestListingDayWhicheverReportArrivesFirst(t *testing.T) {
	// Two records of one issue in one scan can carry catalog entries that
	// disagree, and the scans of two builds arrive in an order nobody
	// controls. The earlier day stands either way.
	each(t, func(t *testing.T, f *fixture) {
		earlier, later := daysAgo(40), daysAgo(20)
		for identifier, order := range map[string][]time.Time{
			"CVE-2026-EARLY": {earlier, later},
			"CVE-2026-LATER": {later, earlier},
		} {
			for _, on := range order {
				day := on
				if _, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(), []finding.Named{{
					Identifier: identifier, Exploited: true, ExploitedOn: &day,
				}}); err != nil {
					t.Fatal(err)
				}
			}
			if got := f.listedOn(t, identifier); !isAt(got, earlier) {
				t.Errorf("%s reported %v in that order is stored as listed on %v, want %s",
					identifier, order, got, earlier)
			}
		}
	})
}

func TestAFindingThatLearnsExploitationFromItsOwnBuildCountsFromTheListingDay(t *testing.T) {
	// Open for a month, then a scan of the same build reports the issue
	// exploited and listed ten days ago. The ten days between the listing and
	// the scan are part of the window, not added to it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		first := f.run(t)
		f.seenAt(t, first, time.Now().UTC().Add(-30*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, first,
			[]finding.Reported{found("CVE-2026-LIST", swss)}); err != nil {
			t.Fatal(err)
		}

		day := daysAgo(10)
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{listed("CVE-2026-LIST", &day)}); err != nil {
			t.Fatal(err)
		}
		row := f.clockOf(t, f.target, "CVE-2026-LIST")
		if !isAt(row.ExploitedLearnedAt, day) {
			t.Errorf("exploitation counts from %v, want the listing day %s",
				row.ExploitedLearnedAt, day)
		}
		if want := day.Add(f.exploitedWindow(t)); !isAt(row.DueAt, want) {
			t.Errorf("due %v, want %s", row.DueAt, want)
		}
	})
}

func TestAFindingThatLearnsExploitationFromAnotherBuildCountsFromTheListingDay(t *testing.T) {
	// The same, where the report naming the listing is another build's: the
	// finding here learns through the issue rather than through its own scan.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		first := f.run(t)
		f.seenAt(t, first, time.Now().UTC().Add(-30*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, first,
			[]finding.Reported{found("CVE-2026-LIST", swss)}); err != nil {
			t.Fatal(err)
		}

		other := f.anotherBranch(t, "next")
		f.shippedTo(t, other, twoConsumers())
		day := daysAgo(10)
		if _, err := f.store.Apply(t.Context(), other, f.runOn(t, other),
			[]finding.Reported{listed("CVE-2026-LIST", &day)}); err != nil {
			t.Fatal(err)
		}
		row := f.clockOf(t, f.target, "CVE-2026-LIST")
		if !row.RankExploited || !isAt(row.ExploitedLearnedAt, day) {
			t.Errorf("exploited %v, counting from %v, want exploited from the listing day %s",
				row.RankExploited, row.ExploitedLearnedAt, day)
		}
		if want := day.Add(f.exploitedWindow(t)); !isAt(row.DueAt, want) {
			t.Errorf("due %v, want %s", row.DueAt, want)
		}
	})
}

func TestAFindingFirstSeenAfterTheListingCountsFromWhenItWasSeen(t *testing.T) {
	// Listed a month ago, recorded so by another build's scan, and first seen
	// here two days ago: exploitation is known from the listing, and nobody
	// could have acted on it here before it was seen, so the window starts at
	// the sighting.
	each(t, func(t *testing.T, f *fixture) {
		day := daysAgo(30)
		other := f.anotherBranch(t, "next")
		f.shippedTo(t, other, twoConsumers())
		if _, err := f.store.Apply(t.Context(), other, f.runOn(t, other),
			[]finding.Reported{listed("CVE-2026-LIST", &day)}); err != nil {
			t.Fatal(err)
		}

		f.shipped(t, twoConsumers())
		seen := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
		run := f.run(t)
		f.seenAt(t, run, seen)
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{listed("CVE-2026-LIST", &day)}); err != nil {
			t.Fatal(err)
		}
		row := f.clockOf(t, f.target, "CVE-2026-LIST")
		if !isAt(row.ExploitedLearnedAt, day) {
			t.Errorf("exploitation counts from %v, want the listing day %s",
				row.ExploitedLearnedAt, day)
		}
		if want := seen.Add(f.exploitedWindow(t)); !isAt(row.DueAt, want) {
			t.Errorf("due %v, want %s: counted from the sighting", row.DueAt, want)
		}
	})
}

func TestAListingDayArrivingLaterReclocksTheIssuesOpenExploitedFindings(t *testing.T) {
	// The issue was learned exploited from a scan that stated no listing day,
	// which is every issue a database from before the day was read holds. The
	// first scan stating an earlier day moves every open exploited finding of
	// the issue onto it, in builds nobody scanned again; a later day, or the
	// same one again, moves nothing.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		opened := f.run(t)
		f.seenAt(t, opened, time.Now().UTC().Add(-60*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, opened,
			[]finding.Reported{found("CVE-2026-LIST", swss)}); err != nil {
			t.Fatal(err)
		}

		// A tag learns it from its own scan, which leaves it off the clock,
		// and the branch above learns it through the issue.
		tag := f.release(t)
		f.shippedTo(t, tag, twoConsumers())
		learned := f.runOn(t, tag)
		f.seenAt(t, learned, time.Now().UTC().Add(-40*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), tag, learned,
			[]finding.Reported{listed("CVE-2026-LIST", nil)}); err != nil {
			t.Fatal(err)
		}
		if got := f.listedOn(t, "CVE-2026-LIST"); got != nil {
			t.Fatalf("a report stating no day stored %s", got)
		}
		if f.clockOf(t, tag, "CVE-2026-LIST").DueAt != nil {
			t.Fatal("the tag carries a deadline before anything was re-clocked")
		}

		other := f.anotherBranch(t, "next")
		f.shippedTo(t, other, twoConsumers())
		day := daysAgo(50)
		if _, err := f.store.Apply(t.Context(), other, f.runOn(t, other),
			[]finding.Reported{listed("CVE-2026-LIST", &day)}); err != nil {
			t.Fatal(err)
		}
		branch := f.clockOf(t, f.target, "CVE-2026-LIST")
		if !isAt(branch.ExploitedLearnedAt, day) {
			t.Errorf("the branch counts exploitation from %v, want %s",
				branch.ExploitedLearnedAt, day)
		}
		want := day.Add(f.exploitedWindow(t))
		if !isAt(branch.DueAt, want) {
			t.Errorf("the branch is due %v, want %s", branch.DueAt, want)
		}
		off := f.clockOf(t, tag, "CVE-2026-LIST")
		if !isAt(off.ExploitedLearnedAt, day) {
			t.Errorf("the tag counts exploitation from %v, want %s", off.ExploitedLearnedAt, day)
		}
		if off.DueAt != nil {
			t.Errorf("re-clocking gave a tag the deadline %s", off.DueAt)
		}

		for _, again := range []time.Time{daysAgo(45), day} {
			if _, err := f.store.Apply(t.Context(), other, f.runOn(t, other),
				[]finding.Reported{listed("CVE-2026-LIST", &again)}); err != nil {
				t.Fatal(err)
			}
			row := f.clockOf(t, f.target, "CVE-2026-LIST")
			if !isAt(row.ExploitedLearnedAt, day) || !isAt(row.DueAt, want) {
				t.Errorf("a report listing it on %s moved the branch to %v, due %v",
					again, row.ExploitedLearnedAt, row.DueAt)
			}
		}
	})
}
