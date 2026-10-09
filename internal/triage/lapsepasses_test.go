// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// lapsableReads counts the reads of every decision a sweep might lapse.
type lapsableReads struct{ n atomic.Int64 }

func (c *lapsableReads) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	if strings.HasPrefix(e.Query, "SELECT de.id FROM") && strings.Contains(e.Query, "NOT EXISTS") {
		c.n.Add(1)
	}
	return ctx
}

func (c *lapsableReads) AfterQuery(context.Context, *bun.QueryEvent) {}

func TestASweepLapsingLessThanABatchReadsTheDecisionsOnce(t *testing.T) {
	// The read of what a sweep may lapse asks about every live decision in
	// the product. One that came back short of a batch named everything
	// lapsable at that moment, so the sweep ends there rather than reading
	// every decision again to find nothing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.build(t, f.product, "2026.03")
		moved := f.component(t, "libfoo", "1.2.4")
		made := f.claims(t, f.at())
		now := time.Now().UTC().Truncate(time.Microsecond)
		const size = 3
		for i := range size {
			place := fmt.Sprintf("place-%d", i)
			if _, err := f.db.DB.NewInsert().Model(&finding.Finding{
				TargetID: in.target, Kind: finding.Vulnerable, VulnerabilityID: f.issue,
				Visibility: access.Public, ComponentID: moved, PlaceIdentity: place,
				LastChangedAt: now, OpenedAt: now, OpenedRunID: &in.run,
			}).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			key, version := fmt.Sprintf("short-%d", i), "1.2.3"
			if _, err := f.db.DB.NewInsert().Model(&triage.Decision{
				ClaimID: made.ClaimID, ProductID: f.product, VulnerabilityID: f.issue,
				PlaceIdentity: place, Visibility: access.Public,
				ComponentUpstreamVersion: &version, State: triage.Proposed,
				NeedsApproval: true, ProposedBy: made.ProposedBy, ProposedAt: now, LiveKey: &key,
			}).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		reads := &lapsableReads{}
		f.db.AddQueryHook(reads)
		lapsed, err := f.store.Lapse(ctx, in.target)
		if err != nil {
			t.Fatal(err)
		}
		if lapsed.Rows != size {
			t.Errorf("the sweep lapsed %d rows, want %d", lapsed.Rows, size)
		}
		if n := reads.n.Load(); n != 1 {
			t.Errorf("the sweep read what it may lapse %d times, want once", n)
		}
	})
}
