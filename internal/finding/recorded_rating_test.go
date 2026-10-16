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

		// A scanner's "unknown" ranks as no word, so it is filled the same
		// way, and a report of "unknown" fills nothing.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Vulnerability)(nil)).
			Set(`"severity" = NULL`).Where(`"id" = ?`, issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		unknown := found("CVE-2026-9", swss)
		unknown.Issue.Severity = "Unknown"
		f.applied(t, unknown)
		if err := f.db.DB.NewSelect().Model((*finding.Vulnerability)(nil)).Column("severity").
			Where(`"id" = ?`, issue).Scan(ctx, &word); err != nil {
			t.Fatal(err)
		}
		if word != "" {
			t.Errorf("a report of unknown filled the issue's word with %q", word)
		}
		if _, err := f.db.DB.NewUpdate().Model((*finding.Vulnerability)(nil)).
			Set(`"severity" = ?`, "Unknown").Where(`"id" = ?`, issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		f.applied(t, found("CVE-2026-9", swss))
		if err := f.db.DB.NewSelect().Model((*finding.Vulnerability)(nil)).Column("severity").
			Where(`"id" = ?`, issue).Scan(ctx, &word); err != nil {
			t.Fatal(err)
		}
		if word != "high" {
			t.Errorf("an issue held at Unknown reads %q after a report, want the scanner's high", word)
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

func TestWithdrawingARatingClaimReturnsARecordedFlawToItsRecordedWord(t *testing.T) {
	// A recorded flaw's word is its product's rating in force until a claim
	// there replaces it. With the claim taken back, the recorded word is in
	// force again and the deadline follows it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.store.Clock(minting)
		f.shipped(t, twoConsumers())
		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PublicTriage, access.PrivateTriage)
		_, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary: "The management socket accepts a request nobody authenticated.",
		})
		if err != nil {
			t.Fatal(err)
		}
		issue := f.issueID(t, identifier)
		due := func(t *testing.T) time.Time {
			t.Helper()
			var at time.Time
			if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).Column("due_at").
				Where(`"vulnerability_id" = ?`, issue).Limit(1).Scan(ctx, &at); err != nil {
				t.Fatal(err)
			}
			return at
		}
		recordedDue := due(t)

		claim, err := f.store.Assess(ctx, who, f.productID, issue, "critical", "Reachable from the network.")
		if err != nil {
			t.Fatal(err)
		}
		if _, word := f.ratings(t, identifier); word != "critical" {
			t.Fatalf("the claim put %q in force, want critical", word)
		}
		if !due(t).Before(recordedDue) {
			t.Fatalf("rated critical, the deadline %s is no sooner than the recorded %s", due(t), recordedDue)
		}
		if _, err := f.store.Withdraw(ctx, who, claim.ID); err != nil {
			t.Fatal(err)
		}
		if _, word := f.ratings(t, identifier); word != "high" {
			t.Errorf("with the claim taken back %q is in force, want the recorded high", word)
		}
		if got := due(t); !got.Equal(recordedDue) {
			t.Errorf("with the claim taken back the deadline is %s, want the recorded %s", got, recordedDue)
		}
	})
}

func TestAMergeCarriesARecordedRatingToTheIssueKept(t *testing.T) {
	// A record and a scanned issue that turn out to be one issue merge into
	// the scanned one, which is filed under the published name. The rating
	// the record's product recorded goes with it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.store.Clock(minting)
		f.shipped(t, twoConsumers())
		f.applied(t, found("CVE-2026-7", teamd))
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		_, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "critical",
			Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Summary: "The management socket accepts a request nobody authenticated.",
		})
		if err != nil {
			t.Fatal(err)
		}
		kept, gone := f.issueID(t, "CVE-2026-7"), f.issueID(t, identifier)
		if kept == gone {
			t.Fatal("the record was filed under the published name before the merge, so this checked nothing")
		}
		f.applied(t, found("CVE-2026-7", teamd, identifier))
		if f.issueID(t, identifier) != kept {
			t.Fatalf("the minted name does not reach the kept issue %d", kept)
		}
		var rows []finding.RecordedRating
		if err := f.db.DB.NewSelect().Model(&rows).
			Where(`"rr"."product_id" = ?`, f.productID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].VulnerabilityID != kept || rows[0].Severity == nil ||
			*rows[0].Severity != "critical" || rows[0].ScoreCenti == nil || *rows[0].ScoreCenti != 980 {
			t.Errorf("the recorded ratings read %+v, want one on the kept issue %d at critical and 9.80", rows, kept)
		}
	})
}

func TestAFilledWordReranksAndReclocksAnotherProductsFinding(t *testing.T) {
	// A word filled in by one product's scan is the published word for every
	// product holding the issue, so a finding another product opened before
	// it, with no rating of its own there, ranks and is clocked by it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		f.shippedTo(t, elsewhere, twoConsumers())
		// One issue already filed under the name the report gives, and one
		// that the report files under a better name, which reach the word by
		// the two ways a report is resolved.
		unrated := []finding.Reported{found("CVE-2026-8", swss), found("GHSA-2026-0009", teamd)}
		for i := range unrated {
			unrated[i].Issue.Severity = ""
		}
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere), unrated); err != nil {
			t.Fatal(err)
		}
		type clock struct {
			Urgency int64      `bun:"urgency"`
			DueAt   *time.Time `bun:"due_at"`
		}
		read := func(t *testing.T, issue int64) clock {
			t.Helper()
			var got clock
			if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).Column("urgency", "due_at").
				Where(`"target_id" = ?`, elsewhere).Where(`"vulnerability_id" = ?`, issue).
				Limit(1).Scan(ctx, &got); err != nil {
				t.Fatal(err)
			}
			return got
		}
		issues := []int64{f.issueID(t, "CVE-2026-8"), f.issueID(t, "GHSA-2026-0009")}
		before := []clock{read(t, issues[0]), read(t, issues[1])}

		f.shipped(t, twoConsumers())
		critical := []finding.Reported{found("CVE-2026-8", swss), found("CVE-2026-9", teamd, "GHSA-2026-0009")}
		for i := range critical {
			critical[i].Issue.Severity = "critical"
		}
		f.applied(t, critical...)

		for i, issue := range issues {
			after := read(t, issue)
			if after.Urgency <= before[i].Urgency {
				t.Errorf("issue %d: the other product's finding ranks %d after the word was filled, want above %d",
					i, after.Urgency, before[i].Urgency)
			}
			if after.DueAt == nil || (before[i].DueAt != nil && !after.DueAt.Before(*before[i].DueAt)) {
				t.Errorf("issue %d: the other product's deadline is %v after a critical word was filled, "+
					"want sooner than %v", i, after.DueAt, before[i].DueAt)
			}
		}
	})
}

func TestARecordedNameFindsNothingForAReaderItIsWithheldFrom(t *testing.T) {
	// A record merged into a scanned issue leaves its minted name among the
	// issue's names. A reader of another product holding the issue, who may
	// not read the record, finds nothing by that name; the published name
	// still finds the issue.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.store.Clock(minting)
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{found("CVE-2026-9", swss)}); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		_, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "critical",
			Summary: "The management socket accepts a request nobody authenticated.",
		})
		if err != nil {
			t.Fatal(err)
		}
		f.applied(t, found("CVE-2026-9", swss, identifier))
		if f.issueID(t, identifier) != f.issueID(t, "CVE-2026-9") {
			t.Fatal("the record did not merge into the scanned issue, so this checked nothing")
		}

		other := f.productOf(t, elsewhere)
		reader := access.NewPerson(2, "elsewhere", false,
			map[int64][]access.Role{other: {access.PublicRead, access.PrivateRead}}, 0)
		search := func(t *testing.T, who access.Subject, scope finding.Scope, term string) int {
			t.Helper()
			groups, _, err := f.store.Groups(ctx, who, scope, 50, 0, finding.Filter{Search: term})
			if err != nil {
				t.Fatal(err)
			}
			return len(groups)
		}
		there := finding.Scope{ProductID: &other}
		if got := search(t, reader, there, identifier); got != 0 {
			t.Errorf("searching the minted name found %d rows for a reader it is withheld from", got)
		}
		if got := search(t, reader, there, "CVE-2026-9"); got == 0 {
			t.Error("searching the published name found nothing")
		}
		recorder := f.planner(t, access.PublicRead, access.PrivateRead)
		if got := search(t, recorder, f.wholeProduct(), identifier); got == 0 {
			t.Error("the recording product's search for its own minted name found nothing")
		}
	})
}
