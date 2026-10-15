// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestARecordedFlawsRatingSortsFiltersAndCountsNothingInAnotherProduct(t *testing.T) {
	// A flaw recorded in one product is rated by that product. Another
	// product holding the same issue sorts, filters and counts its own
	// findings by the published rating, and the issue publishes none, so
	// nothing a reader there does can find out how bad the recorder judged
	// it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.store.Clock(minting)
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		_, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "critical",
			Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Summary: "The management socket accepts a request nobody authenticated.",
		})
		if err != nil {
			t.Fatal(err)
		}
		issue, err := finding.NewVulnerabilities(f.db.DB).ByName(ctx, identifier)
		if err != nil {
			t.Fatal(err)
		}

		// A second product, scanned, holding the same issue at a place of
		// its own and disclosed there.
		cat := catalog.NewStore(f.db.DB)
		other, err := cat.DeclareProduct(ctx, "switchd", "Switch Daemon")
		if err != nil {
			t.Fatal(err)
		}
		stream, err := cat.DeclareStream(ctx, other.ID, "main", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.DeclareVariant(ctx, other.ID, "mellanox", true)
		if err != nil {
			t.Fatal(err)
		}
		target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		mine := f.target
		f.target = target.ID
		f.shipped(t, twoConsumers())
		run := f.run(t)
		f.target = mine
		if _, err := f.db.DB.NewInsert().Model(&finding.Finding{
			TargetID: target.ID, Kind: finding.Vulnerable, Visibility: access.Public,
			VulnerabilityID: issue, ComponentID: f.componentID(t, swss.Name),
			PlaceIdentity: finding.PlaceIdentity(swss.Name, ""), OpenedAt: time.Now().UTC(),
			OpenedRunID: &run,
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		type told struct {
			listed, critical, score int
			counted                 int
		}
		read := func(t *testing.T, reader access.Subject, scope finding.Scope) told {
			t.Helper()
			all, _, err := f.store.Groups(ctx, reader, scope, 50, 0,
				finding.Filter{SortBy: finding.BySeverity})
			if err != nil {
				t.Fatal(err)
			}
			worst, _, err := f.store.Groups(ctx, reader, scope, 50, 0,
				finding.Filter{MinSeverity: "critical"})
			if err != nil {
				t.Fatal(err)
			}
			got := told{listed: len(all), critical: len(worst)}
			for _, group := range all {
				if group.Vulnerability == identifier && group.ScoreCenti > got.score {
					got.score = group.ScoreCenti
				}
			}
			aging, err := f.store.Remediation(ctx, reader, scope, time.Time{}, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			for _, bucket := range aging.Aging {
				got.counted += bucket.BySeverity["critical"]
			}
			return got
		}

		elsewhere := access.NewPerson(2, "elsewhere", false,
			map[int64][]access.Role{other.ID: {access.PublicRead, access.PrivateRead}}, 0)
		there := finding.Scope{ProductID: &other.ID, StreamID: &stream.ID, VariantID: &variant.ID}
		if got := read(t, elsewhere, there); got.listed == 0 || got.critical != 0 ||
			got.score != 0 || got.counted != 0 {
			t.Errorf("a reader of the other product alone was told %+v: "+
				"want the issue listed, and nothing critical, scored or counted as critical", got)
		}
		recorder := f.planner(t, access.PublicRead, access.PrivateRead)
		if got := read(t, recorder, f.scope); got.critical == 0 || got.score != 980 || got.counted == 0 {
			t.Errorf("the recording product was told %+v: want its own flaw critical and scored 9.80", got)
		}
	})
}
