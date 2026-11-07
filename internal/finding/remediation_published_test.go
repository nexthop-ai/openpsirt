// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// published records the date a public vulnerability database states for an
// issue, as the date pass writes it.
func (f *fixture) published(t *testing.T, issue int64, at time.Time) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Table("vulnerability").
		Set(`"published_at" = ?`, at.UTC().Truncate(time.Microsecond)).
		Where(`"id" = ?`, issue).Exec(t.Context()); err != nil {
		t.Fatalf("date issue %d: %v", issue, err)
	}
}

// withinADayOf reports whether a duration is within a day of so many days.
func withinADayOf(took time.Duration, days int) bool {
	want := time.Duration(days) * 24 * time.Hour
	return took > want-24*time.Hour && took < want+24*time.Hour
}

func TestTimeToFixFromPublicationLeavesAnUndatedIssueOutAndCountsIt(t *testing.T) {
	// Two issues opened here ten days before their fix, one published thirty
	// days before it and one with no date. The first-sighting figure holds
	// both; the publication figure holds the dated one, and the undated one is
	// counted apart rather than timed from its first sighting.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-2", libnl))
		now := time.Now().UTC()
		for _, issue := range []string{"CVE-2026-1", "CVE-2026-2"} {
			f.aged(t, issue, now.Add(-10*24*time.Hour))
			f.closeIt(t, issue, finding.Upgraded, now)
		}
		f.published(t, f.issueID(t, "CVE-2026-1"), now.Add(-30*24*time.Hour))

		got, err := f.store.Remediation(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Fixed != 2 {
			t.Fatalf("counted %d fixes, want both issues", got.Fixed)
		}
		if took := got.TimeToFix["high"]; !withinADayOf(took, 10) {
			t.Errorf("from first sighting took %s, want about ten days", took)
		}
		if took, held := got.FromPublication["high"]; !held || !withinADayOf(took, 30) {
			t.Errorf("from publication took %s (present %v), want about thirty days from the dated issue alone",
				took, held)
		}
		if got.Undated["high"] != 1 {
			t.Errorf("counted %d undated fixes, want the one issue with no date", got.Undated["high"])
		}
	})
}

func TestAnIssueFixedBeforeItsPublicationTookNoTimeFromIt(t *testing.T) {
	// A pre-disclosure fix: opened here twenty days before its fix, published
	// five days after it. At disclosure nothing was left to fix, so it counts
	// as no time rather than a negative one pulling the average down, and it
	// stays in the figure rather than leaving the fixes made earliest out.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-2", libnl))
		now := time.Now().UTC()
		for _, issue := range []string{"CVE-2026-1", "CVE-2026-2"} {
			f.aged(t, issue, now.Add(-20*24*time.Hour))
			f.closeIt(t, issue, finding.Upgraded, now.Add(-24*time.Hour))
		}
		f.published(t, f.issueID(t, "CVE-2026-1"), now.Add(4*24*time.Hour))
		f.published(t, f.issueID(t, "CVE-2026-2"), now.Add(-21*24*time.Hour))

		got, err := f.store.Remediation(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		// Zero and twenty days average to ten; a negative five would make it
		// about seven and a half, and leaving the first out would make it twenty.
		if took := got.FromPublication["high"]; !withinADayOf(took, 10) {
			t.Errorf("from publication took %s, want about ten days", took)
		}
		if len(got.Undated) != 0 {
			t.Errorf("counted %v undated, want none", got.Undated)
		}
	})
}

func TestAMergedIssueIsTimedFromThePublicationDateOfTheIssueKept(t *testing.T) {
	// The occurrences are under an undated name, and another name dated forty
	// days back merges with it: the fix is then timed from the date the
	// merged issue holds, and no longer counted undated.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		f.foundOnLibnl(t)
		now := time.Now().UTC()
		f.aged(t, "CVE-2026-1", now.Add(-10*24*time.Hour))
		f.closeIt(t, "CVE-2026-1", finding.Upgraded, now)

		names := finding.NewVulnerabilities(f.db.DB)
		if _, err := names.Intern(ctx, []finding.Named{{Identifier: "GHSA-2026-abcd-efgh"}}); err != nil {
			t.Fatal(err)
		}
		f.published(t, f.issueID(t, "GHSA-2026-abcd-efgh"), now.Add(-40*24*time.Hour))
		measured := func(t *testing.T) *finding.Remediation {
			t.Helper()
			got, err := f.store.Remediation(ctx, f.holding(t, access.PublicRead),
				f.wholeProduct(), time.Time{}, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			return got
		}
		if got := measured(t); got.Undated["high"] != 1 || len(got.FromPublication) != 0 {
			t.Fatalf("before the merge: %v from publication, %v undated, want one undated",
				got.FromPublication, got.Undated)
		}

		if _, err := names.Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-1", Aliases: []string{"GHSA-2026-abcd-efgh"}},
		}); err != nil {
			t.Fatalf("merge the two: %v", err)
		}
		got := measured(t)
		if took := got.FromPublication["high"]; !withinADayOf(took, 40) {
			t.Errorf("from publication took %s, want about forty days from the merged issue's date", took)
		}
		if len(got.Undated) != 0 {
			t.Errorf("counted %v undated after the merge, want none", got.Undated)
		}
	})
}

func TestTimeToFixFromPublicationCountsOnlyWhatTheReaderReads(t *testing.T) {
	// An undisclosed issue's fix, dated, and an undisclosed undated one: a
	// reader of disclosed findings is told neither figure nor the undated
	// count, and a reader of undisclosed findings is told both.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-2", libnl))
		now := time.Now().UTC()
		for _, issue := range []string{"CVE-2026-1", "CVE-2026-2"} {
			f.aged(t, issue, now.Add(-10*24*time.Hour))
			f.closeIt(t, issue, finding.Upgraded, now)
		}
		f.published(t, f.issueID(t, "CVE-2026-1"), now.Add(-30*24*time.Hour))
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"visibility" = ?`, access.Private).Where("1 = 1").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		public, err := f.store.Remediation(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if len(public.FromPublication) != 0 || len(public.Undated) != 0 {
			t.Errorf("a reader of disclosed findings was told %v from publication and %v undated",
				public.FromPublication, public.Undated)
		}
		private, err := f.store.Remediation(ctx, f.holding(t, access.PrivateRead),
			f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if !withinADayOf(private.FromPublication["high"], 30) || private.Undated["high"] != 1 {
			t.Errorf("a reader of undisclosed findings was told %v from publication and %v undated",
				private.FromPublication, private.Undated)
		}
	})
}
