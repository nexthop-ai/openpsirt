// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
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
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		june := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
		march := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
		place := finding.PlaceIdentity(libnl.Name, swss.Name)
		for i, one := range []struct {
			issue, to string
			by        time.Time
		}{{"CVE-2026-1", "1.9", june}, {"CVE-2026-2", "1.10", march}} {
			claim := claimSaying(t, f.db, somebody.ID, "upgrade-needed")
			if _, err := f.db.DB.NewUpdate().Table("claim").
				Set("committed_to = ?", one.by).Set("upgrade_to = ?", one.to).
				Where("id = ?", claim).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.DB.NewInsert().Model(&map[string]any{
				"claim_id": claim, "product_id": f.productID,
				"vulnerability_id": f.issueID(t, one.issue),
				"place_identity":   place, "visibility": "public", "state": "approved",
				"needs_approval": true, "proposed_by": somebody.ID,
				"proposed_at":                time.Now().UTC(),
				"component_upstream_version": libnl.Version,
				"live_key":                   []string{"promise-one", "promise-two"}[i],
			}).TableExpr(`"decision"`).Exec(ctx); err != nil {
				t.Fatal(err)
			}
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
