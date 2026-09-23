// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// closeIt marks every open row for one issue as closed, for a reason, at a
// moment — which is what a scan does, expressed directly so a test can put a
// fix a fortnight in the past.
func (f *fixture) closeIt(t *testing.T, issue string, because finding.Closure, at time.Time) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
		Set("closed_at = ?", at).
		Set("closed_because = ?", because).
		Where("vulnerability_id = ?", f.issueID(t, issue)).
		Where("closed_at IS NULL").
		Exec(t.Context()); err != nil {
		t.Fatalf("close %s: %v", issue, err)
	}
}

// aged moves when an issue's rows opened, so that a fix can have taken time.
func (f *fixture) aged(t *testing.T, issue string, at time.Time) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
		Set("opened_at = ?", at).
		Where("vulnerability_id = ?", f.issueID(t, issue)).
		Exec(t.Context()); err != nil {
		t.Fatalf("age %s: %v", issue, err)
	}
}

func TestAChurnedVersionIsNotCountedAsAFix(t *testing.T) {
	// and the rule that makes the whole figure worth having. A bump that
	// carried the issue with it closed one row and opened another with the
	// same flaw in it, and a scanner that stopped reporting something
	// explained nothing. Counting either as a fix measures churn and
	// reports it as progress — the number improves while nothing does.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
			found("CVE-2026-2", libnl),
			found("CVE-2026-3", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		for _, issue := range []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"} {
			f.aged(t, issue, now.Add(-10*24*time.Hour))
		}
		// One genuinely fixed, one carried into the next version, one the
		// scanner simply stopped mentioning.
		f.closeIt(t, "CVE-2026-1", finding.Upgraded, now.Add(-24*time.Hour))
		f.closeIt(t, "CVE-2026-2", finding.Superseded, now.Add(-24*time.Hour))
		f.closeIt(t, "CVE-2026-3", finding.Unexplained, now.Add(-24*time.Hour))

		got, err := f.store.Remediation(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Fixed != 1 {
			t.Errorf("counted %d fixes, want the one issue that actually went away", got.Fixed)
		}
	})
}

func TestHowLongAFixTookIsCountedPerIssueAndNotPerPlace(t *testing.T) {
	// One kernel flaw across sixty modules is one thing that was fixed. An
	// average weighted by how far a component fans out measures the dependency
	// graph rather than anybody's work.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// The same library under two consumers, so one issue sits at two
		// places and would be counted twice by a naive average.
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{swss, teamd, libnl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss}, {Parent: root, Child: teamd},
				{Parent: swss, Child: libnl}, {Parent: teamd, Child: libnl},
			},
		})
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		var places int
		if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			ColumnExpr("COUNT(*)").Where("closed_at IS NULL").Scan(ctx, &places); err != nil {
			t.Fatal(err)
		}
		if places < 2 {
			t.Fatalf("the fixture put this at %d places, want more than one", places)
		}

		now := time.Now().UTC()
		f.aged(t, "CVE-2026-1", now.Add(-10*24*time.Hour))
		f.closeIt(t, "CVE-2026-1", finding.Upgraded, now)

		got, err := f.store.Remediation(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Fixed != 1 {
			t.Errorf("one issue at %d places counted as %d fixes", places, got.Fixed)
		}
		// Ten days, however many places it sat at.
		for band, took := range got.TimeToFix {
			if took < 9*24*time.Hour || took > 11*24*time.Hour {
				t.Errorf("%s took %s, want about ten days", band, took)
			}
		}
	})
}

func TestWhatIsAgingIsCountedInTheBucketsPeopleAskIn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		f.aged(t, "CVE-2026-1", now.Add(-2*24*time.Hour))
		f.aged(t, "CVE-2026-2", now.Add(-120*24*time.Hour))

		got, err := f.store.Remediation(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int{}
		for _, bucket := range got.Aging {
			counts[bucket.Label] = bucket.Open
		}
		if counts["under a week"] != 1 {
			t.Errorf("a two-day-old issue landed in %v", counts)
		}
		if counts["over three months"] != 1 {
			t.Errorf("a four-month-old issue landed in %v", counts)
		}
	})
}

func TestSomebodyWhoReadsNothingMeasuresNothing(t *testing.T) {
	// The same rule as every other aggregate: a figure is over what the
	// asker may see, and it is the data layer that decides.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		f.aged(t, "CVE-2026-1", time.Now().UTC().Add(-5*24*time.Hour))
		f.closeIt(t, "CVE-2026-1", finding.Upgraded, time.Now().UTC())

		stranger := access.NewPerson(9, "nobody@example.com", false,
			map[int64][]access.Role{f.productID + 999: {access.PublicRead}}, 0)
		got, err := f.store.Remediation(ctx, stranger, finding.Scope{}, time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if got != nil && got.Fixed != 0 {
			t.Errorf("somebody holding nothing here was told about %d fixes", got.Fixed)
		}
	})
}
