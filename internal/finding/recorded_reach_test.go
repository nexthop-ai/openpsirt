// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAnUndisclosedRecordsWordsReachNoReaderOfDisclosedWorkAlone(t *testing.T) {
	// A flaw recorded here writes its summary as the issue's description, its
	// minted name among the issue's names, and its addresses on the issue. The
	// issue row is shared, so every read of those three asks whether such a
	// record sits out of the reader's reach.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl, "GHSA-aaaa-bbbb-cccc")}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if len(open) == 0 {
			t.Fatal("the scan opened nothing, so this checked nothing")
		}
		issue, component := open[0].VulnerabilityID, open[0].ComponentID
		const summary = "The management socket answers before anyone has authenticated."
		if _, err := f.db.DB.NewUpdate().Model((*finding.Vulnerability)(nil)).
			Set(`"description" = ?`, summary).Where(`"id" = ?`, issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		const address = "https://example.com/advisories/socket"
		if _, err := f.db.DB.NewInsert().Model(&finding.Reference{
			VulnerabilityID: issue, URL: address, Kind: finding.Patch, URLIdentity: address,
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		// The record, undisclosed, beside the scanned finding.
		recorded := open[0]
		recorded.ID, recorded.Kind, recorded.Visibility = 0, finding.Entered, access.Private
		recorded.PlaceIdentity = finding.PlaceIdentity("libnl", "recorded-by-hand")
		if _, err := f.db.DB.NewInsert().Model(&recorded).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		vulnerabilities := finding.NewVulnerabilities(f.db.DB)
		read := func(t *testing.T, who access.Subject) (said []string, names, addresses int) {
			t.Helper()
			named, err := vulnerabilities.DescribeFor(ctx, who, issue)
			if err != nil {
				t.Fatal(err)
			}
			points, err := vulnerabilities.PointsAtFor(ctx, who, issue)
			if err != nil {
				t.Fatal(err)
			}
			evidence, err := f.store.Detail(ctx, who, f.target, issue, component)
			if err != nil {
				t.Fatal(err)
			}
			listed, _, _, err := f.store.AtComponent(ctx, who, f.target, component, "", 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) == 0 {
				t.Fatal("the component lists nothing, so its summary was not read")
			}
			matched, _, _, err := f.store.AtComponent(ctx, who, f.target, component, "socket", 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			said = []string{named.Description, evidence.Description, listed[0].Summary}
			if len(matched) > 0 {
				said = append(said, "matched")
			}
			return said, len(named.Aliases) + len(evidence.Aliases),
				len(points) + len(evidence.References)
		}

		said, names, addresses := read(t, f.holding(t, access.PublicTriage))
		for _, one := range said {
			if one != "" {
				t.Errorf("a reader of disclosed work alone was told the undisclosed record's words: %q", one)
			}
		}
		if names != 0 || addresses != 0 {
			t.Errorf("a reader of disclosed work alone was told %d names and %d addresses", names, addresses)
		}

		said, names, addresses = read(t, f.holding(t, access.PublicTriage, access.PrivateTriage))
		want := []string{summary, summary, summary, "matched"}
		if len(said) != len(want) {
			t.Fatalf("a reader of both halves was told %q, want %q", said, want)
		}
		for i := range want {
			if said[i] != want[i] {
				t.Errorf("a reader of both halves was told %q, want %q", said[i], want[i])
			}
		}
		if names != 2 || addresses != 2 {
			t.Errorf("a reader of both halves was told %d names and %d addresses, want 2 and 2", names, addresses)
		}
	})
}

func TestAnUndisclosedRecordsScoreReachesNoReaderOfDisclosedWorkAlone(t *testing.T) {
	// A recorded flaw's score is its product's own, held off the issue row,
	// and the issue page and a finding's evidence carry it only where every
	// record of the issue is in the reader's reach. A rating a feed
	// published stays for everybody.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if len(open) == 0 {
			t.Fatal("the scan opened nothing, so this checked nothing")
		}
		issue, component := open[0].VulnerabilityID, open[0].ComponentID
		if _, err := f.db.DB.NewDelete().Model((*finding.CVSS)(nil)).
			Where(`"vulnerability_id" = ?`, issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewInsert().Model(&finding.CVSS{VulnerabilityID: issue, Generation: 2,
			ScoreCenti: 750, Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", Source: "nvd@nist.gov"}).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		word, score := "critical", 980
		vector, version := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1"
		if _, err := f.db.DB.NewInsert().Model(&finding.RecordedRating{
			VulnerabilityID: issue, ProductID: f.productID, Severity: &word,
			ScoreCenti: &score, Vector: &vector, ScoreVersion: &version,
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		recorded := open[0]
		recorded.ID, recorded.Kind, recorded.Visibility = 0, finding.Entered, access.Private
		recorded.PlaceIdentity = finding.PlaceIdentity("libnl", "recorded-by-hand")
		if _, err := f.db.DB.NewInsert().Model(&recorded).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		vulnerabilities := finding.NewVulnerabilities(f.db.DB)
		type told struct{ score, ratings int }
		read := func(t *testing.T, who access.Subject) []told {
			t.Helper()
			named, err := vulnerabilities.DescribeFor(ctx, who, issue)
			if err != nil {
				t.Fatal(err)
			}
			evidence, err := f.store.Detail(ctx, who, f.target, issue, component)
			if err != nil {
				t.Fatal(err)
			}
			return []told{
				{int(named.Score * 100), len(named.Ratings)},
				{evidence.ScoreCenti, len(evidence.Ratings)},
			}
		}
		for i, got := range read(t, f.holding(t, access.PublicTriage)) {
			if got != (told{0, 1}) {
				t.Errorf("read %d: a reader of disclosed work alone was told %+v, "+
					"want no score and the one published rating", i, got)
			}
		}
		for i, got := range read(t, f.holding(t, access.PublicTriage, access.PrivateTriage)) {
			if got != (told{980, 1}) {
				t.Errorf("read %d: a reader of both halves was told %+v, "+
					"want the recorded score and the one published rating", i, got)
			}
		}
	})
}
