// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestACodeFindingsFlawIsReadOnlyBySomebodyOnItsCase(t *testing.T) {
	// The record names an undisclosed flaw, so the store answers it only to a
	// reader of the product's undisclosed work, somebody on the flaw's case or
	// somebody granted the code finding, and answers anybody else as it
	// answers a code finding never recorded.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		const occurrence = "recorded-code-finding"
		f.shipped(t, twoConsumers())
		f.applied(t, found("CVE-2026-1", libnl))
		flaw := f.issueID(t, "CVE-2026-1")
		person, err := access.NewStore(f.db.DB).Ensure(ctx, "recorder@example.com", "Recorder", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewInsert().Model(&finding.CodeFindingFlaw{
			ProductID: f.productID, OccurrenceIdentity: occurrence, VulnerabilityID: flaw,
			Visibility: access.SecurityTesting, RecordedBy: person.ID, RecordedAt: time.Now().UTC().Truncate(time.Second),
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		public := f.holding(t, access.PublicRead)
		for name, who := range map[string]access.Subject{
			"a reader of undisclosed work": f.holding(t, access.PublicRead, access.PrivateRead),
			"somebody on the flaw's case":  public.OnCases(map[int64][]int64{f.productID: {flaw}}),
			"somebody granted the code finding": public.OnCodeFindings(
				map[int64][]string{f.productID: {occurrence}}),
		} {
			if h, err := f.store.CodeFindingFlawFor(ctx, who, f.productID, occurrence); err != nil || h == nil {
				t.Errorf("%s was answered %v and %v, want the record", name, h, err)
			}
		}
		if h, err := f.store.CodeFindingFlawFor(ctx, public, f.productID, occurrence); err != nil || h != nil {
			t.Errorf("a reader of disclosed work alone was answered %v and %v, want nothing", h, err)
		}
	})
}

func TestWhoIsOnACodeFindingIsRefusedAlikeWhetherOrNotItWasRecorded(t *testing.T) {
	// Managing who is on a code finding is for a reader of the product's
	// security testing work. Anybody else is refused before the record is
	// looked up, so the refusal says nothing of whether there is one.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		const recorded = "recorded-code-finding"
		f.shipped(t, twoConsumers())
		f.applied(t, found("CVE-2026-1", libnl))
		flaw := f.issueID(t, "CVE-2026-1")
		person, err := access.NewStore(f.db.DB).Ensure(ctx, "recorder@example.com", "Recorder", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewInsert().Model(&finding.CodeFindingFlaw{
			ProductID: f.productID, OccurrenceIdentity: recorded, VulnerabilityID: flaw,
			Visibility: access.SecurityTesting, RecordedBy: person.ID, RecordedAt: time.Now().UTC().Truncate(time.Second),
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		granted := f.holding(t, access.PublicRead).OnCodeFindings(map[int64][]string{f.productID: {recorded}})
		for _, occurrence := range []string{recorded, "never-recorded"} {
			if _, err := f.store.CodeFindingFlawManaged(ctx, granted, f.productID, occurrence); !errors.Is(err, access.ErrDenied) {
				t.Errorf("somebody granted the code finding asking about %s was answered %v, want a refusal",
					occurrence, err)
			}
		}
		tester := f.holding(t, access.PublicRead, access.SecurityTestingRead)
		if h, err := f.store.CodeFindingFlawManaged(ctx, tester, f.productID, recorded); err != nil || h == nil {
			t.Errorf("a reader of security testing work was answered %v and %v, want the record", h, err)
		}
		if h, err := f.store.CodeFindingFlawManaged(ctx, tester, f.productID, "never-recorded"); err != nil || h != nil {
			t.Errorf("a code finding never recorded was answered %v and %v, want nothing", h, err)
		}
	})
}
