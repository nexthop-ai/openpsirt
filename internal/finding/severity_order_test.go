// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// severityLeaders is what leads each list ordered by severity, as the
// component the leading row is open against: the findings list, the
// by-component view and the list spanning products.
func severityLeaders(t *testing.T, f *fixture, who access.Subject) map[string]string {
	t.Helper()
	ctx := t.Context()
	filter := finding.Filter{SortBy: finding.BySeverity}
	led := map[string]string{}
	groups, _, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0, filter)
	if err != nil {
		t.Fatal(err)
	}
	across, _, err := f.store.Anywhere(ctx, who, 50, 0, filter)
	if err != nil {
		t.Fatal(err)
	}
	components, _, err := f.store.ComponentGroups(ctx, who, f.wholeProduct(), 50, 0, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) == 0 || len(across) == 0 || len(components) == 0 {
		t.Fatalf("a list is empty: %d groups, %d across products, %d components",
			len(groups), len(across), len(components))
	}
	led["the findings list"] = groups[0].Component
	led["the list spanning products"] = across[0].Component
	led["the by-component view"] = components[0].Component
	return led
}

func TestTheSeverityOrderRanksTheBandBeforeTheScore(t *testing.T) {
	// A critical the feed gave no score is worse than a high scored 8.1. The
	// score orders the issues inside one band and never moves one across.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{
			ranked("CVE-2026-1", libnl, "critical", 0),
			ranked("CVE-2026-2", swss, "high", 8.1),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)
		for list, got := range severityLeaders(t, f, who) {
			if got != libnl.Name {
				t.Errorf("%s ordered by severity leads with %q rather than the package holding the unscored critical",
					list, got)
			}
		}
	})
}

func TestTheSeverityOrderReadsTheProductsOwnRating(t *testing.T) {
	// A product rating an issue worse than the feed did moves it up every list
	// ordered by severity in that product, past an issue the feed scored higher.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{
			ranked("CVE-2026-1", swss, "high", 8.8),
			ranked("CVE-2026-2", libnl, "medium", 5.3),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)
		for list, got := range severityLeaders(t, f, who) {
			if got != swss.Name {
				t.Errorf("%s ordered by severity leads with %q before any rating of the product's own", list, got)
			}
		}
		f.rate(t, f.productID, "CVE-2026-2", "critical")
		for list, got := range severityLeaders(t, f, who) {
			if got != libnl.Name {
				t.Errorf("%s ordered by severity leads with %q rather than the package holding the issue "+
					"the product rates critical", list, got)
			}
		}
	})
}

func TestTheSeverityOrderRanksAnUnratedIssueByItsScore(t *testing.T) {
	// An issue no recognized word rates sorts in the band of its score, as
	// urgency ranks it: "unknown" scored 9.8 is a critical, above a high
	// scored 7.0. The filters' medium fold does not reach the order.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{
			ranked("CVE-2026-1", libnl, "unknown", 9.8),
			ranked("CVE-2026-2", swss, "high", 7.0),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)
		for list, got := range severityLeaders(t, f, who) {
			if got != libnl.Name {
				t.Errorf("%s ordered by severity leads with %q rather than the package holding the unrated 9.8",
					list, got)
			}
		}
	})
}

func TestTheSeverityOrderRanksAnUnratedUnscoredIssueBelowALow(t *testing.T) {
	// An issue with no recognized word and no score sorts below every band,
	// as urgency ranks it and the row reads "Unrated", rather than in the
	// medium band the filters fold it to.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{
			ranked("CVE-2026-1", libnl, "unknown", 0),
			ranked("CVE-2026-2", swss, "low", 2.0),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)
		for list, got := range severityLeaders(t, f, who) {
			if got != swss.Name {
				t.Errorf("%s ordered by severity leads with %q rather than the package holding the low",
					list, got)
			}
		}
	})
}
