// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// An issue answers when it was published as OSV states, says unknown where
// OSV was asked and holds no record, and unasked before anybody asked.
func TestAnIssueSaysWhenItWasPublished(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.Scanned(t)
		db := r.DB.DB
		issue, err := finding.NewVulnerabilities(db).ByName(ctx, "CVE-2026-9999")
		if err != nil {
			t.Fatal(err)
		}
		type page struct {
			Published string `json:"published"`
			Modified  string `json:"modified"`
			Dates     string `json:"dates"`
		}
		var got page
		httpapitest.Read(t, r, "private", "/v1/issues/CVE-2026-9999", &got)
		if got.Dates != "unasked" || got.Published != "" {
			t.Errorf("before asking the issue reads %+v, want unasked", got)
		}

		asked := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
		if _, err := db.NewUpdate().Table("vulnerability").Set(`"dates_asked_at" = ?`, asked).
			Where(`"id" = ?`, issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		got = page{}
		httpapitest.Read(t, r, "private", "/v1/issues/CVE-2026-9999", &got)
		if got.Dates != "unknown" || got.Published != "" {
			t.Errorf("asked with no record the issue reads %+v, want unknown", got)
		}

		published := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
		if _, err := db.NewUpdate().Table("vulnerability").Set(`"published_at" = ?`, published).
			Set(`"modified_at" = ?`, asked).Where(`"id" = ?`, issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		got = page{}
		httpapitest.Read(t, r, "private", "/v1/issues/CVE-2026-9999", &got)
		if got.Dates != "stated" || got.Published == "" || got.Modified == "" {
			t.Errorf("dated, the issue reads %+v, want both dates", got)
		}
		if when, err := time.Parse(time.RFC3339, got.Published); err != nil || !when.Equal(published) {
			t.Errorf("published reads %q, want %v", got.Published, published)
		}
	})
}
