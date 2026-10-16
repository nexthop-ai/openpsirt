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
	// it. The list leaves out the summary the record wrote, too.
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
			summary                 string
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
				if group.Vulnerability == identifier && group.Summary != "" {
					got.summary = group.Summary
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
			got.score != 0 || got.counted != 0 || got.summary != "" {
			t.Errorf("a reader of the other product alone was told %+v: "+
				"want the issue listed, and nothing critical, scored, counted as critical or summarized", got)
		}
		recorder := f.planner(t, access.PublicRead, access.PrivateRead)
		if got := read(t, recorder, f.scope); got.critical == 0 || got.score != 980 || got.counted == 0 ||
			got.summary == "" {
			t.Errorf("the recording product was told %+v: want its own flaw critical, scored 9.80 and summarized", got)
		}
	})
}

func TestARecordedFlawFiledUnderAPublishedNameTakesTheFeedsWord(t *testing.T) {
	// A recorded flaw's issue holds no word of its own. A scanner reporting
	// it under a published name, with the minted one beside it, files the
	// record there and gives the issue the scanner's word, so another product
	// holding that name reads how the world rates it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.store.Clock(minting)
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		_, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "critical",
			Summary: "The management socket accepts a request nobody authenticated.",
		})
		if err != nil {
			t.Fatal(err)
		}
		issue := f.issueID(t, identifier)
		f.applied(t, found("CVE-2026-9", swss, identifier))
		if refiled := f.issueID(t, "CVE-2026-9"); refiled != issue {
			t.Fatalf("the published name reaches issue %d, want the record's %d", refiled, issue)
		}
		var word string
		if err := f.db.DB.NewSelect().Model((*finding.Vulnerability)(nil)).Column("severity").
			Where(`"id" = ?`, issue).Scan(ctx, &word); err != nil {
			t.Fatal(err)
		}
		if word != "high" {
			t.Errorf("the issue's word is %q, want the scanner's high", word)
		}

		// An issue already filed under the published name and holding no
		// word, as an upgrade leaves one whose word was the record's, takes
		// the word from the next report of it.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Vulnerability)(nil)).
			Set(`"severity" = NULL`).Where(`"id" = ?`, issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		f.applied(t, found("CVE-2026-9", swss))
		if err := f.db.DB.NewSelect().Model((*finding.Vulnerability)(nil)).Column("severity").
			Where(`"id" = ?`, issue).Scan(ctx, &word); err != nil {
			t.Fatal(err)
		}
		if word != "high" {
			t.Errorf("the issue's word is %q after a rescan, want the scanner's high", word)
		}
	})
}

func TestTheRecordingProductsReleaseNoteAndComponentCarryTheScoreItRecorded(t *testing.T) {
	// A recorded flaw's score is held off the issue row, so a reader that
	// takes the score from the row alone says nothing about how bad the
	// recording product judged its own flaw.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.store.Clock(minting)
		earlier := f.anotherBuild(t, "1.0")
		f.shippedTo(t, earlier, twoConsumers())
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
		reader := f.planner(t, access.PublicRead, access.PrivateRead)

		comparison, err := f.store.Compare(ctx, reader, earlier, f.target, true)
		if err != nil {
			t.Fatal(err)
		}
		noted := -1
		for _, entry := range comparison.Newly {
			if entry.Vulnerability == identifier {
				noted = entry.ScoreCenti
			}
		}
		if noted != 980 {
			t.Errorf("the release note scores the recorded flaw %d, want 980", noted)
		}

		places, _, _, err := f.store.AtComponent(ctx, reader, f.target, f.componentID(t, swss.Name), "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(places) == 0 {
			t.Fatal("the component lists nothing, so this checked nothing")
		}
		for _, place := range places {
			if place.SeverityCenti != 980 {
				t.Errorf("the component scores the recorded flaw %d, want 980", place.SeverityCenti)
			}
		}
	})
}
