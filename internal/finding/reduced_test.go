// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// The reports that reduce their findings before counting them: the trend,
// what is aging, what each release holds. Each groups the places first and
// joins what it counts by to what is left, so these pin that the reduction
// keeps what the count needs.

// placesOf is the open findings of one issue in the fixture's build, keyed by
// the name of the consumer each sits under.
func (f *fixture) placesOf(t *testing.T, identifier string) map[string]finding.Finding {
	t.Helper()
	issue := f.issueID(t, identifier)
	var consumers []struct {
		ID   int64  `bun:"id"`
		Name string `bun:"name"`
	}
	if err := f.db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`f.id AS "id"`).ColumnExpr(`uc.name AS "name"`).
		Where("f.vulnerability_id = ?", issue).Where("f.target_id = ?", f.target).
		Where("f.closed_at IS NULL").Scan(t.Context(), &consumers); err != nil {
		t.Fatal(err)
	}
	byID := map[int64]finding.Finding{}
	for _, row := range f.open(t) {
		byID[row.ID] = row
	}
	out := map[string]finding.Finding{}
	for _, consumer := range consumers {
		out[consumer.Name] = byID[consumer.ID]
	}
	return out
}

// decidedAt writes a decision of this product at one place, keyed on the
// versions given, live where key is not empty.
func (f *fixture) decidedAt(t *testing.T, by int64, at finding.Finding, state, component, consumer, key string) {
	t.Helper()
	row := map[string]any{
		"claim_id":   claimBy(t, f.db, by),
		"product_id": f.productID, "vulnerability_id": at.VulnerabilityID,
		"place_identity": at.PlaceIdentity, "visibility": "public",
		"state": state, "needs_approval": true, "proposed_by": by,
		"proposed_at":                time.Now().UTC(),
		"component_upstream_version": component,
		"consumer_upstream_version":  consumer,
	}
	if key != "" {
		row["live_key"] = key
	}
	if _, err := f.db.DB.NewInsert().Model(&row).TableExpr(`"decision"`).Exec(t.Context()); err != nil {
		t.Fatalf("record a %s claim: %v", state, err)
	}
}

// somebodyElse is a person to have proposed what a test records.
func (f *fixture) somebodyElse(t *testing.T) int64 {
	t.Helper()
	person, err := access.NewStore(f.db.DB).Ensure(t.Context(), "somebody@example.com", "Them", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return person.ID
}

func TestAnIssueAgingInTwoBucketsIsUndecidedOnlyInTheBucketWhosePlacesNobodyAnswered(t *testing.T) {
	// An issue counts in every bucket it has a place in, and whether it is
	// answered is asked of the places in that bucket. Answered at the old
	// place and not at the new, it is undecided among the new and not among
	// the old.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		places := f.placesOf(t, "CVE-2026-1")
		now := time.Now().UTC()
		for name, opened := range map[string]time.Time{
			swss.Name:  now.Add(-2 * 24 * time.Hour),
			teamd.Name: now.Add(-120 * 24 * time.Hour),
		} {
			if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
				Set("opened_at = ?", opened).Where("id = ?", places[name].ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		f.decidedAt(t, f.somebodyElse(t), places[teamd.Name], "approved", libnl.Version, teamd.Version, "old-place")

		got, err := f.store.Remediation(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string][2]int{
			"under a week": {1, 1}, "one to four weeks": {0, 0},
			"one to three months": {0, 0}, "over three months": {1, 0},
		}
		if len(got.Aging) != len(want) {
			t.Fatalf("%d buckets, want %d", len(got.Aging), len(want))
		}
		for _, bucket := range got.Aging {
			if pair := [2]int{bucket.Open, bucket.Undecided}; pair != want[bucket.Label] {
				t.Errorf("%q holds %d open, %d undecided; want %v", bucket.Label, pair[0], pair[1], want[bucket.Label])
			}
			sum := 0
			for _, n := range bucket.BySeverity {
				sum += n
			}
			if sum != bucket.Open {
				t.Errorf("%q splits %d open into %v", bucket.Label, bucket.Open, bucket.BySeverity)
			}
		}
	})
}

func TestATrendReadsTheProductsOwnRatingOfAnIssueOpenAtManyPlaces(t *testing.T) {
	// The places are reduced before the rating is joined, so the rating has
	// to be the product's own as well as the published one when it arrives.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		f.rate(t, f.productID, "CVE-2026-1", "critical")
		points, err := f.store.Trend(ctx, f.holding(t, access.PublicRead), f.wholeProduct(),
			time.Time{}, 24*time.Hour, 2, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		last := points[len(points)-1]
		if last.Open != 2 || last.BySeverity["critical"] != 1 || last.BySeverity["high"] != 1 {
			t.Errorf("two issues at two places each, one rated critical here: open %d, split %v",
				last.Open, last.BySeverity)
		}
	})
}

func TestAReleaseCountsAnIssueAtAComponentOnceAtTheProductsRating(t *testing.T) {
	// One library under two consumers is one thing to answer, and the band
	// it is counted in is the one this product gave it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		f.rate(t, f.productID, "CVE-2026-1", "low")
		releases, err := f.store.Releases(ctx, f.holding(t, access.PublicRead), f.productID)
		if err != nil {
			t.Fatal(err)
		}
		var held bool
		for _, release := range releases {
			if release.Open == 0 {
				continue
			}
			held = true
			if release.Open != 1 || release.BySeverity["low"] != 1 {
				t.Errorf("%s · %s holds %d open, split %v; want 1, rated low",
					release.Stream, release.Variant, release.Open, release.BySeverity)
			}
		}
		if !held {
			t.Error("no release holds anything, so nothing here was checked")
		}
	})
}
