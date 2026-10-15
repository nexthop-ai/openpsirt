// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Where two promises to upgrade stand over one component in one build, the
// date and the version reported are one promise's: the latest date, and the
// version that promise names. "1.10" sorts before "1.9" as text, so a version
// chosen apart from its date is a different promise's.
func TestAPromiseAcrossBuildsIsOnePromisesDateAndVersion(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-2", libnl))
		somebody := f.somebodyElse(t)
		june := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
		march := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
		place := finding.PlaceIdentity(libnl.Name, swss.Name)
		for i, one := range []struct {
			issue, to string
			by        time.Time
		}{{"CVE-2026-1", "1.9", june}, {"CVE-2026-2", "1.10", march}} {
			claim := claimSaying(t, f.db, somebody, "upgrade-needed")
			if _, err := f.db.DB.NewUpdate().Table("claim").
				Set(`"committed_to" = ?`, one.by).Set(`"upgrade_to" = ?`, one.to).
				Where(`"id" = ?`, claim).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			f.decision(t, decisionRow{
				By: somebody, Claim: claim, Issue: f.issueID(t, one.issue), Place: place,
				State: "approved", Component: ptr(libnl.Version),
				Key: []string{"promise-one", "promise-two"}[i],
			})
		}

		builds, err := f.store.AcrossBuilds(ctx, f.holding(t, access.PublicTriage), f.wholeProduct(), libnl.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 {
			t.Fatalf("%d builds carry it, want one", len(builds))
		}
		got := builds[0]
		if got.CommittedTo == nil || !got.CommittedTo.Equal(june) || got.UpgradeTo != "1.9" {
			t.Errorf("the promise reads as %q by %v, want 1.9 by June — one promise's date and version",
				got.UpgradeTo, got.CommittedTo)
		}
	})
}

// Which of two promises stands over a component: one naming a version over one
// naming none, then one with a date over one without, then the latest date,
// then the later claim. Each case is decided by its own rule alone, and the
// promise that loses is made second where the rule is anything but the claim,
// so neither order nor identifier settles it by accident.
func TestThePromiseThatStandsNamesAVersionThenADateThenTheLatestThenTheLaterClaim(t *testing.T) {
	june := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	march := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	type said struct {
		to string
		by *time.Time
	}
	for _, c := range []struct {
		name          string
		stands, loses said
		later         bool
	}{
		{"a version over none, whatever the dates", said{"3.9.0", &march}, said{"", &june}, false},
		{"a date over none", said{"3.9.0", &march}, said{"4.0", nil}, false},
		{"the latest date", said{"3.9.0", &june}, said{"4.0", &march}, false},
		{"the later claim where they are alike", said{"3.9.0", &june}, said{"4.0", &june}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				ctx := t.Context()
				f.shipped(t, through(libnl))
				f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-2", libnl))
				somebody := f.somebodyElse(t)
				promise := func(issue string, one said) {
					t.Helper()
					claim := claimSaying(t, f.db, somebody, "upgrade-needed")
					if _, err := f.db.DB.NewUpdate().Table("claim").
						Set(`"committed_to" = ?`, one.by).Set(`"upgrade_to" = ?`, one.to).
						Where(`"id" = ?`, claim).Exec(ctx); err != nil {
						t.Fatal(err)
					}
					f.decision(t, decisionRow{
						By: somebody, Claim: claim, Issue: f.issueID(t, issue),
						Place: finding.PlaceIdentity(libnl.Name, swss.Name), State: "approved",
						Component: ptr(libnl.Version), Key: fmt.Sprint("promise-", claim),
					})
				}
				if c.later {
					promise("CVE-2026-2", c.loses)
					promise("CVE-2026-1", c.stands)
				} else {
					promise("CVE-2026-1", c.stands)
					promise("CVE-2026-2", c.loses)
				}

				builds, err := f.store.AcrossBuilds(ctx, f.holding(t, access.PublicTriage), f.wholeProduct(), libnl.Name)
				if err != nil {
					t.Fatal(err)
				}
				if len(builds) != 1 {
					t.Fatalf("%d builds carry it, want one", len(builds))
				}
				got := builds[0]
				if got.UpgradeTo != c.stands.to || (got.CommittedTo == nil) != (c.stands.by == nil) ||
					(got.CommittedTo != nil && !got.CommittedTo.Equal(*c.stands.by)) {
					t.Errorf("the promise reads as %q by %v, want %q by %v",
						got.UpgradeTo, got.CommittedTo, c.stands.to, c.stands.by)
				}
			})
		})
	}
}

// A place two promises reach is one place. The promises are read beside the
// places they stand over, so a place joined to each of them is counted twice
// unless the promises are one row per place first.
func TestAPlaceUnderTwoPromisesIsCountedOnce(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		f.foundOnLibnl(t)
		somebody := f.somebodyElse(t)
		june := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
		for _, version := range []string{libnl.Version, "3.6.0"} {
			claim := claimSaying(t, f.db, somebody, "upgrade-needed")
			if _, err := f.db.DB.NewUpdate().Table("claim").
				Set(`"committed_to" = ?`, june).Set(`"upgrade_to" = ?`, "3.9.0").
				Where(`"id" = ?`, claim).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			f.decision(t, decisionRow{
				By: somebody, Claim: claim, Issue: f.issueID(t, "CVE-2026-1"),
				Place: finding.PlaceIdentity(libnl.Name, swss.Name), State: "approved",
				Component: &version, Key: fmt.Sprint("promise-", claim),
			})
		}

		builds, err := f.store.AcrossBuilds(ctx, f.holding(t, access.PublicTriage), f.wholeProduct(), libnl.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 {
			t.Fatalf("%d builds carry it, want one", len(builds))
		}
		if got := builds[0]; got.Places != 1 || got.Issues != 1 || got.UpgradeTo != "3.9.0" {
			t.Errorf("%d places and %d issues promised to %q, want the one place once, promised to 3.9.0",
				got.Places, got.Issues, got.UpgradeTo)
		}
	})
}
